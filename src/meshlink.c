/*
    meshlink.c -- Implementation of the MeshLink API.
    Copyright (C) 2014-2021 Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"
#include <pthread.h>

#include "crypto.h"
#include "ecdsagen.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "packmsg.h"
#include "prf.h"
#include "protocol.h"
#include "sockaddr.h"
#include "utils.h"
#include "xalloc.h"
#include "ed25519/sha512.h"
#include "devtools.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
__thread meshlink_errno_t meshlink_errno;
meshlink_log_cb_t global_log_cb;
meshlink_log_level_t global_log_level;

typedef bool (*search_node_by_condition_t)(const node_t *, const void *);

static int rstrip(char *value) {
	int len = strlen(value);

	while(len && strchr("\t\r\n ", value[len - 1])) {
		value[--len] = 0;
	}

	return len;
}

static bool is_valid_hostname(const char *hostname) {
	if(!*hostname) {
		return false;
	}

	for(const char *p = hostname; *p; p++) {
		if(!(isalnum(*p) || *p == '-' || *p == '.' || *p == ':')) {
			return false;
		}
	}

	return true;
}

static bool is_valid_port(const char *port) {
	if(!*port) {
		return false;
	}

	if(isdigit(*port)) {
		char *end;
		unsigned long int result = strtoul(port, &end, 10);
		return result && result < 65536 && !*end;
	}

	for(const char *p = port; *p; p++) {
		if(!(isalnum(*p) || *p == '-')) {
			return false;
		}
	}

	return true;
}

static void set_timeout(int sock, int timeout) {
#ifdef _WIN32
	DWORD tv = timeout;
#else
	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout - tv.tv_sec * 1000) * 1000;
#endif
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

struct socket_in_netns_params {
	int domain;
	int type;
	int protocol;
	int netns;
	int fd;
};

#ifdef HAVE_SETNS
static void *socket_in_netns_thread(void *arg) {
	struct socket_in_netns_params *params = arg;

	if(setns(params->netns, CLONE_NEWNET) == -1) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	params->fd = socket(params->domain, params->type, params->protocol);

	return NULL;
}
#endif // HAVE_SETNS

static int socket_in_netns(int domain, int type, int protocol, int netns) {
	if(netns == -1) {
		return socket(domain, type, protocol);
	}

#ifdef HAVE_SETNS
	struct socket_in_netns_params params = {domain, type, protocol, netns, -1};

	pthread_t thr;

	if(pthread_create(&thr, NULL, socket_in_netns_thread, &params) == 0) {
		if(pthread_join(thr, NULL) != 0) {
			abort();
		}
	}

	return params.fd;
#else
	return -1;
#endif // HAVE_SETNS

}

static bool write_main_config_files(meshlink_handle_t *mesh) {
	if(!mesh->confbase) {
		return true;
	}

	uint8_t buf[4096];

	/* Write the main config file */
	packmsg_output_t out = {buf, sizeof buf};

	packmsg_add_uint32(&out, MESHLINK_CONFIG_VERSION);
	packmsg_add_str(&out, mesh->name);
	packmsg_add_bin(&out, ecdsa_get_private_key(mesh->private_key), 96);
	packmsg_add_nil(&out); // Invitation keys are not supported
	packmsg_add_uint16(&out, atoi(mesh->myport));

	if(!packmsg_output_ok(&out)) {
		return false;
	}

	config_t config = {buf, packmsg_output_size(&out, buf)};

	if(!main_config_write(mesh, "current", &config, mesh->config_key)) {
		return false;
	}

	/* Write our own host config file */
	if(!node_write_config(mesh, mesh->self, true)) {
		return false;
	}

	return true;
}

typedef struct {
	meshlink_handle_t *mesh;
	int sock;
	char cookie[18 + 32];
	char hash[18];
	bool success;
	sptps_t sptps;
	char *data;
	size_t thedatalen;
	size_t blen;
	char line[4096];
	char buffer[4096];
} join_state_t;

static bool finalize_join(join_state_t *state, const void *buf, uint16_t len) {
	meshlink_handle_t *mesh = state->mesh;
	packmsg_input_t in = {buf, len};
	uint32_t version = packmsg_get_uint32(&in);

	if(version != MESHLINK_INVITATION_VERSION) {
		logger(mesh, MESHLINK_ERROR, "Invalid invitation version!\n");
		return false;
	}

	char *name = packmsg_get_str_dup(&in);
	packmsg_skip_element(&in); // submesh_name
	dev_class_t devclass = packmsg_get_int32(&in);
	uint32_t count = packmsg_get_array(&in);

	if(!name || !check_id(name)) {
		logger(mesh, MESHLINK_DEBUG, "No valid Name found in invitation!\n");
		free(name);
		return false;
	}

	if(!count) {
		logger(mesh, MESHLINK_ERROR, "Incomplete invitation file!\n");
		free(name);
		return false;
	}

	free(mesh->name);
	free(mesh->self->name);
	mesh->name = name;
	mesh->self->name = xstrdup(name);
	mesh->self->devclass = devclass == DEV_CLASS_UNKNOWN ? mesh->devclass : devclass;

	// Initialize configuration directory
	if(!config_init(mesh, "current")) {
		return false;
	}

	if(!write_main_config_files(mesh)) {
		return false;
	}

	// Write host config files
	for(uint32_t i = 0; i < count; i++) {
		const void *data;
		uint32_t data_len = packmsg_get_bin_raw(&in, &data);

		if(!data_len) {
			logger(mesh, MESHLINK_ERROR, "Incomplete invitation file!\n");
			return false;
		}

		packmsg_input_t in2 = {data, data_len};
		uint32_t version2 = packmsg_get_uint32(&in2);
		char *name2 = packmsg_get_str_dup(&in2);

		if(!packmsg_input_ok(&in2) || version2 != MESHLINK_CONFIG_VERSION || !check_id(name2)) {
			free(name2);
			packmsg_input_invalidate(&in);
			break;
		}

		if(!check_id(name2)) {
			free(name2);
			break;
		}

		if(!strcmp(name2, mesh->name)) {
			logger(mesh, MESHLINK_ERROR, "Secondary chunk would overwrite our own host config file.\n");
			free(name2);
			meshlink_errno = MESHLINK_EPEER;
			return false;
		}

		node_t *n = new_node();
		n->name = name2;

		config_t config = {data, data_len};

		if(!node_read_from_config(mesh, n, &config)) {
			free_node(n);
			logger(mesh, MESHLINK_ERROR, "Invalid host config file in invitation file!\n");
			meshlink_errno = MESHLINK_EPEER;
			return false;
		}

		if(i == 0) {
			/* The first host config file is of the inviter itself;
			 * remember the address we are currently using for the invitation connection.
			 */
			sockaddr_t sa;
			socklen_t salen = sizeof(sa);

			if(getpeername(state->sock, &sa.sa, &salen) == 0) {
				node_add_recent_address(mesh, n, &sa);
			}
		}

		if(!node_write_config(mesh, n, true)) {
			free_node(n);
			return false;
		}

		node_add(mesh, n);
	}

	/* Ensure the configuration directory metadata is on disk */
	if(!config_sync(mesh, "current") || (mesh->confbase && !sync_path(mesh->confbase))) {
		return false;
	}

	if(!mesh->inviter_commits_first) {
		devtool_set_inviter_commits_first(false);
	}

	sptps_send_record(&state->sptps, 1, ecdsa_get_public_key(mesh->private_key), 32);

	if(mesh->confbase) {
		logger(mesh, MESHLINK_DEBUG, "Configuration stored in: %s\n", mesh->confbase);
	}

	return true;
}

static bool invitation_send(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	join_state_t *state = handle;
	const char *ptr = data;

	while(len) {
		int result = send(state->sock, ptr, len, 0);

		if(result == -1 && errno == EINTR) {
			continue;
		} else if(result <= 0) {
			return false;
		}

		ptr += result;
		len -= result;
	}

	return true;
}

static bool invitation_receive(void *handle, uint8_t type, const void *msg, uint16_t len) {
	join_state_t *state = handle;
	meshlink_handle_t *mesh = state->mesh;

	if(mesh->inviter_commits_first) {
		switch(type) {
		case SPTPS_HANDSHAKE:
			return sptps_send_record(&state->sptps, 2, state->cookie, 18 + 32);

		case 1:
			break;

		case 0:
			if(!finalize_join(state, msg, len)) {
				return false;
			}

			logger(mesh, MESHLINK_DEBUG, "Invitation successfully accepted.\n");
			shutdown(state->sock, SHUT_RDWR);
			state->success = true;
			break;

		default:
			return false;
		}
	} else {
		switch(type) {
		case SPTPS_HANDSHAKE:
			return sptps_send_record(&state->sptps, 0, state->cookie, 18);

		case 0:
			return finalize_join(state, msg, len);

		case 1:
			logger(mesh, MESHLINK_DEBUG, "Invitation successfully accepted.\n");
			shutdown(state->sock, SHUT_RDWR);
			state->success = true;
			break;

		default:
			return false;
		}
	}

	return true;
}

static bool recvline(join_state_t *state) {
	char *newline = NULL;

	while(!(newline = memchr(state->buffer, '\n', state->blen))) {
		int result = recv(state->sock, state->buffer + state->blen, sizeof(state)->buffer - state->blen, 0);

		if(result == -1 && errno == EINTR) {
			continue;
		} else if(result <= 0) {
			return false;
		}

		state->blen += result;
	}

	if((size_t)(newline - state->buffer) >= sizeof(state->line)) {
		return false;
	}

	size_t len = newline - state->buffer;

	memcpy(state->line, state->buffer, len);
	state->line[len] = 0;
	memmove(state->buffer, newline + 1, state->blen - len - 1);
	state->blen -= len + 1;

	return true;
}

static bool sendline(int fd, const char *format, ...) {
	char buffer[4096];
	char *p = buffer;
	int blen = 0;
	va_list ap;

	va_start(ap, format);
	blen = vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	if(blen < 1 || (size_t)blen >= sizeof(buffer)) {
		return false;
	}

	buffer[blen] = '\n';
	blen++;

	while(blen) {
		int result = send(fd, p, blen, MSG_NOSIGNAL);

		if(result == -1 && errno == EINTR) {
			continue;
		} else if(result <= 0) {
			return false;
		}

		p += result;
		blen -= result;
	}

	return true;
}

static const char *errstr[] = {
	[MESHLINK_OK] = "No error",
	[MESHLINK_EINVAL] = "Invalid argument",
	[MESHLINK_ENOMEM] = "Out of memory",
	[MESHLINK_ENOENT] = "No such node",
	[MESHLINK_EEXIST] = "Node already exists",
	[MESHLINK_EINTERNAL] = "Internal error",
	[MESHLINK_ERESOLV] = "Could not resolve hostname",
	[MESHLINK_ESTORAGE] = "Storage error",
	[MESHLINK_ENETWORK] = "Network error",
	[MESHLINK_EPEER] = "Error communicating with peer",
	[MESHLINK_ENOTSUP] = "Operation not supported",
	[MESHLINK_EBUSY] = "MeshLink instance already in use",
	[MESHLINK_EBLACKLISTED] = "Node is blacklisted",
};

const char *meshlink_strerror(meshlink_errno_t err) {
	if((int)err < 0 || err >= sizeof(errstr) / sizeof(*errstr)) {
		return "Invalid error code";
	}

	return errstr[err];
}

static bool ecdsa_keygen(meshlink_handle_t *mesh) {
	logger(mesh, MESHLINK_DEBUG, "Generating ECDSA keypair:\n");

	mesh->private_key = ecdsa_generate();

	if(!mesh->private_key) {
		logger(mesh, MESHLINK_ERROR, "Error during key generation!\n");
		meshlink_errno = MESHLINK_EINTERNAL;
		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "Done.\n");

	return true;
}

static struct timespec idle(event_loop_t *loop, void *data) {
	(void)loop;
	(void)data;

	return (struct timespec) {
		3600, 0
	};
}

static bool meshlink_setup(meshlink_handle_t *mesh) {
	if(!config_destroy(mesh->confbase, "new")) {
		logger(mesh, MESHLINK_ERROR, "Could not delete configuration in %s/new: %s\n", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(!config_destroy(mesh->confbase, "old")) {
		logger(mesh, MESHLINK_ERROR, "Could not delete configuration in %s/old: %s\n", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(!config_init(mesh, "current")) {
		logger(mesh, MESHLINK_ERROR, "Could not set up configuration in %s/current: %s\n", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(!ecdsa_keygen(mesh)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		return false;
	}

	mesh->myport = xstrdup("0");

	/* Create a node for ourself */

	mesh->self = new_node();
	mesh->self->name = xstrdup(mesh->name);
	mesh->self->devclass = mesh->devclass;
	mesh->self->ecdsa = ecdsa_set_public_key(ecdsa_get_public_key(mesh->private_key));
	mesh->self->session_id = mesh->session_id;

	if(!write_main_config_files(mesh)) {
		logger(mesh, MESHLINK_ERROR, "Could not write main config files into %s/current: %s\n", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	/* Ensure the configuration directory metadata is on disk */
	if(!config_sync(mesh, "current")) {
		return false;
	}

	return true;
}

static bool meshlink_read_config(meshlink_handle_t *mesh) {
	config_t config;

	if(!main_config_read(mesh, "current", &config, mesh->config_key)) {
		logger(NULL, MESHLINK_ERROR, "Could not read main configuration file!");
		return false;
	}

	packmsg_input_t in = {config.buf, config.len};
	const void *private_key;

	uint32_t version = packmsg_get_uint32(&in);
	char *name = packmsg_get_str_dup(&in);
	uint32_t private_key_len = packmsg_get_bin_raw(&in, &private_key);
	packmsg_skip_element(&in); // Invitation key is not supported
	uint16_t myport = packmsg_get_uint16(&in);

	if(!packmsg_done(&in) || version != MESHLINK_CONFIG_VERSION || private_key_len != 96) {
		logger(NULL, MESHLINK_ERROR, "Error parsing main configuration file!");
		free(name);
		config_free(&config);
		return false;
	}

	if(mesh->name && strcmp(mesh->name, name)) {
		logger(NULL, MESHLINK_ERROR, "Configuration is for a different name (%s)!", name);
		meshlink_errno = MESHLINK_ESTORAGE;
		free(name);
		config_free(&config);
		return false;
	}

	free(mesh->name);
	mesh->name = name;
	xasprintf(&mesh->myport, "%u", myport);
	mesh->private_key = ecdsa_set_private_key(private_key);
	config_free(&config);

	/* Create a node for ourself and read our host configuration file */

	mesh->self = new_node();
	mesh->self->name = xstrdup(name);
	mesh->self->devclass = mesh->devclass;
	mesh->self->session_id = mesh->session_id;

	if(!node_read_public_key(mesh, mesh->self)) {
		logger(NULL, MESHLINK_ERROR, "Could not read our host configuration file!");
		meshlink_errno = MESHLINK_ESTORAGE;
		free_node(mesh->self);
		mesh->self = NULL;
		return false;
	}

	return true;
}

#ifdef HAVE_SETNS
static void *setup_network_in_netns_thread(void *arg) {
	meshlink_handle_t *mesh = arg;

	if(setns(mesh->netns, CLONE_NEWNET) != 0) {
		return NULL;
	}

	bool success = setup_network(mesh);
	return success ? arg : NULL;
}
#endif // HAVE_SETNS

meshlink_open_params_t *meshlink_open_params_init(const char *confbase, const char *name, const char *appname, dev_class_t devclass) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_params_init(%s, %s, %s, %d)", confbase, name, appname, devclass);

	if(!confbase || !*confbase) {
		logger(NULL, MESHLINK_ERROR, "No confbase given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(!appname || !*appname) {
		logger(NULL, MESHLINK_ERROR, "No appname given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(strchr(appname, ' ')) {
		logger(NULL, MESHLINK_ERROR, "Invalid appname given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(name && !check_id(name)) {
		logger(NULL, MESHLINK_ERROR, "Invalid name given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(devclass < 0 || devclass >= DEV_CLASS_COUNT) {
		logger(NULL, MESHLINK_ERROR, "Invalid devclass given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	meshlink_open_params_t *params = xzalloc(sizeof * params);

	params->confbase = xstrdup(confbase);
	params->name = name ? xstrdup(name) : NULL;
	params->appname = xstrdup(appname);
	params->devclass = devclass;
	params->netns = -1;

	xasprintf(&params->lock_filename, "%s" SLASH "meshlink.lock", confbase);

	return params;
}

bool meshlink_open_params_set_netns(meshlink_open_params_t *params, int netns) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_params_set_netnst(%d)", netns);

	if(!params) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	params->netns = netns;

	return true;
}

bool meshlink_open_params_set_storage_key(meshlink_open_params_t *params, const void *key, size_t keylen) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_params_set_storage_key(%p, %zu)", key, keylen);

	if(!params) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if((!key && keylen) || (key && !keylen)) {
		logger(NULL, MESHLINK_ERROR, "Invalid key length!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	params->key = key;
	params->keylen = keylen;

	return true;
}

bool meshlink_open_params_set_storage_policy(meshlink_open_params_t *params, meshlink_storage_policy_t policy) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_params_set_storage_policy(%d)", policy);

	if(!params) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	params->storage_policy = policy;

	return true;
}

bool meshlink_open_params_set_lock_filename(meshlink_open_params_t *params, const char *filename) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_params_set_lock_filename(%s)", filename);

	if(!params || !filename) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	free(params->lock_filename);
	params->lock_filename = xstrdup(filename);

	return true;
}

bool meshlink_encrypted_key_rotate(meshlink_handle_t *mesh, const void *new_key, size_t new_keylen) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_encrypted_key_rotate(%p, %zu)", new_key, new_keylen);

	if(!mesh || !new_key || !new_keylen) {
		logger(mesh, MESHLINK_ERROR, "Invalid arguments given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	// Create hash for the new key
	void *new_config_key;
	new_config_key = xmalloc(CHACHA_POLY1305_KEYLEN);

	if(!prf(new_key, new_keylen, "MeshLink configuration key", 26, new_config_key, CHACHA_POLY1305_KEYLEN)) {
		logger(mesh, MESHLINK_ERROR, "Error creating new configuration key!\n");
		meshlink_errno = MESHLINK_EINTERNAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	// Copy contents of the "current" confbase sub-directory to "new" confbase sub-directory with the new key

	if(!config_copy(mesh, "current", mesh->config_key, "new", new_config_key)) {
		logger(mesh, MESHLINK_ERROR, "Could not set up configuration in %s/old: %s\n", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	devtool_keyrotate_probe(1);

	// Rename confbase/current/ to confbase/old

	if(!config_rename(mesh, "current", "old")) {
		logger(mesh, MESHLINK_ERROR, "Cannot rename %s/current to %s/old\n", mesh->confbase, mesh->confbase);
		meshlink_errno = MESHLINK_ESTORAGE;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	devtool_keyrotate_probe(2);

	// Rename confbase/new/ to confbase/current

	if(!config_rename(mesh, "new", "current")) {
		logger(mesh, MESHLINK_ERROR, "Cannot rename %s/new to %s/current\n", mesh->confbase, mesh->confbase);
		meshlink_errno = MESHLINK_ESTORAGE;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	devtool_keyrotate_probe(3);

	// Cleanup the "old" confbase sub-directory

	if(!config_destroy(mesh->confbase, "old")) {
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	// Change the mesh handle key with new key

	free(mesh->config_key);
	mesh->config_key = new_config_key;

	pthread_mutex_unlock(&mesh->mutex);

	return true;
}

void meshlink_open_params_free(meshlink_open_params_t *params) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_params_free()");

	if(!params) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	free(params->confbase);
	free(params->name);
	free(params->appname);
	free(params->lock_filename);

	free(params);
}

/// Device class traits
static const dev_class_traits_t default_class_traits[DEV_CLASS_COUNT] = {
	{ .pingtimeout = 5, .pinginterval = 60, .maxtimeout = 900, .min_connects = 3, .max_connects = 10000, .edge_weight = 1 }, // DEV_CLASS_BACKBONE
	{ .pingtimeout = 5, .pinginterval = 60, .maxtimeout = 900, .min_connects = 3, .max_connects = 100, .edge_weight = 3 },   // DEV_CLASS_STATIONARY
	{ .pingtimeout = 5, .pinginterval = 60, .maxtimeout = 900, .min_connects = 3, .max_connects = 3, .edge_weight = 6 },     // DEV_CLASS_PORTABLE
	{ .pingtimeout = 5, .pinginterval = 60, .maxtimeout = 900, .min_connects = 1, .max_connects = 1, .edge_weight = 9 },     // DEV_CLASS_UNKNOWN
};

meshlink_handle_t *meshlink_open(const char *confbase, const char *name, const char *appname, dev_class_t devclass) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open(%s, %s, %s, %d)", confbase, name, appname, devclass);

	if(!confbase || !*confbase) {
		logger(NULL, MESHLINK_ERROR, "No confbase given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	char lock_filename[PATH_MAX];
	snprintf(lock_filename, sizeof(lock_filename), "%s" SLASH "meshlink.lock", confbase);

	/* Create a temporary struct on the stack, to avoid allocating and freeing one. */
	meshlink_open_params_t params = {
		.confbase = (char *)confbase,
		.lock_filename = lock_filename,
		.name = (char *)name,
		.appname = (char *)appname,
		.devclass = devclass,
		.netns = -1,
	};

	return meshlink_open_ex(&params);
}

meshlink_handle_t *meshlink_open_encrypted(const char *confbase, const char *name, const char *appname, dev_class_t devclass, const void *key, size_t keylen) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_encrypted(%s, %s, %s, %d, %p, %zu)", confbase, name, appname, devclass, key, keylen);

	if(!confbase || !*confbase) {
		logger(NULL, MESHLINK_ERROR, "No confbase given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	char lock_filename[PATH_MAX];
	snprintf(lock_filename, sizeof(lock_filename), "%s" SLASH "meshlink.lock", confbase);

	/* Create a temporary struct on the stack, to avoid allocating and freeing one. */
	meshlink_open_params_t params = {
		.confbase = (char *)confbase,
		.lock_filename = lock_filename,
		.name = (char *)name,
		.appname = (char *)appname,
		.devclass = devclass,
		.netns = -1,
	};

	if(!meshlink_open_params_set_storage_key(&params, key, keylen)) {
		return false;
	}

	return meshlink_open_ex(&params);
}

meshlink_handle_t *meshlink_open_ephemeral(const char *name, const char *appname, dev_class_t devclass) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_ephemeral(%s, %s, %d)", name, appname, devclass);

	if(!name) {
		logger(NULL, MESHLINK_ERROR, "No name given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(!check_id(name)) {
		logger(NULL, MESHLINK_ERROR, "Invalid name given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(!appname || !*appname) {
		logger(NULL, MESHLINK_ERROR, "No appname given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(strchr(appname, ' ')) {
		logger(NULL, MESHLINK_ERROR, "Invalid appname given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(devclass < 0 || devclass >= DEV_CLASS_COUNT) {
		logger(NULL, MESHLINK_ERROR, "Invalid devclass given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	/* Create a temporary struct on the stack, to avoid allocating and freeing one. */
	meshlink_open_params_t params = {
		.name = (char *)name,
		.appname = (char *)appname,
		.devclass = devclass,
		.netns = -1,
	};

	return meshlink_open_ex(&params);
}

meshlink_handle_t *meshlink_open_ex(const meshlink_open_params_t *params) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_open_ex()");

	// Validate arguments provided by the application
	if(!params->appname || !*params->appname) {
		logger(NULL, MESHLINK_ERROR, "No appname given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(strchr(params->appname, ' ')) {
		logger(NULL, MESHLINK_ERROR, "Invalid appname given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(params->name && !check_id(params->name)) {
		logger(NULL, MESHLINK_ERROR, "Invalid name given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(params->devclass < 0 || params->devclass >= DEV_CLASS_COUNT) {
		logger(NULL, MESHLINK_ERROR, "Invalid devclass given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if((params->key && !params->keylen) || (!params->key && params->keylen)) {
		logger(NULL, MESHLINK_ERROR, "Invalid key length!\n");
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	meshlink_handle_t *mesh = xzalloc(sizeof(meshlink_handle_t));

	if(params->confbase) {
		mesh->confbase = xstrdup(params->confbase);
	}

	mesh->appname = xstrdup(params->appname);
	mesh->devclass = params->devclass;
	mesh->netns = params->netns;
	mesh->log_cb = global_log_cb;
	mesh->log_level = global_log_level;
	mesh->packet = xmalloc(sizeof(vpn_packet_t));

	randomize(&mesh->prng_state, sizeof(mesh->prng_state));

	do {
		randomize(&mesh->session_id, sizeof(mesh->session_id));
	} while(mesh->session_id == 0);

	memcpy(mesh->dev_class_traits, default_class_traits, sizeof(default_class_traits));

	mesh->name = params->name ? xstrdup(params->name) : NULL;

	// Hash the key
	if(params->key) {
		mesh->config_key = xmalloc(CHACHA_POLY1305_KEYLEN);

		if(!prf(params->key, params->keylen, "MeshLink configuration key", 26, mesh->config_key, CHACHA_POLY1305_KEYLEN)) {
			logger(NULL, MESHLINK_ERROR, "Error creating configuration key!\n");
			meshlink_close(mesh);
			meshlink_errno = MESHLINK_EINTERNAL;
			return NULL;
		}
	}

	// initialize mutexes and conds
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);

	if(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
		abort();
	}

	pthread_mutex_init(&mesh->mutex, &attr);
	pthread_cond_init(&mesh->cond, NULL);

	mesh->threadstarted = false;
	event_loop_init(&mesh->loop);
	mesh->loop.data = mesh;

	meshlink_queue_init(&mesh->outpacketqueue);

	// Atomically lock the configuration directory.
	if(!main_config_lock(mesh, params->lock_filename)) {
		meshlink_close(mesh);
		return NULL;
	}

	// If no configuration exists yet, create it.

	bool new_configuration = false;

	if(!meshlink_confbase_exists(mesh)) {
		if(!mesh->name) {
			logger(NULL, MESHLINK_ERROR, "No configuration files found!\n");
			meshlink_close(mesh);
			meshlink_errno = MESHLINK_ESTORAGE;
			return NULL;
		}

		if(!meshlink_setup(mesh)) {
			logger(NULL, MESHLINK_ERROR, "Cannot create initial configuration\n");
			meshlink_close(mesh);
			return NULL;
		}

		new_configuration = true;
	} else {
		if(!meshlink_read_config(mesh)) {
			logger(NULL, MESHLINK_ERROR, "Cannot read main configuration\n");
			meshlink_close(mesh);
			return NULL;
		}
	}

	mesh->storage_policy = params->storage_policy;

#ifdef HAVE_MINGW
	struct WSAData wsa_state;
	WSAStartup(MAKEWORD(2, 2), &wsa_state);
#endif

	// Setup up everything
	// TODO: we should not open listening sockets yet

	bool success = false;

	if(mesh->netns != -1) {
#ifdef HAVE_SETNS
		pthread_t thr;

		if(pthread_create(&thr, NULL, setup_network_in_netns_thread, mesh) == 0) {
			void *retval = NULL;
			success = pthread_join(thr, &retval) == 0 && retval;
		}

#else
		meshlink_errno = MESHLINK_EINTERNAL;
		return NULL;

#endif // HAVE_SETNS
	} else {
		success = setup_network(mesh);
	}

	if(!success) {
		meshlink_close(mesh);
		meshlink_errno = MESHLINK_ENETWORK;
		return NULL;
	}

	if(!node_write_config(mesh, mesh->self, new_configuration)) {
		logger(NULL, MESHLINK_ERROR, "Cannot update configuration\n");
		return NULL;
	}

	idle_set(&mesh->loop, idle, mesh);

	logger(NULL, MESHLINK_DEBUG, "meshlink_open returning\n");
	return mesh;
}

static void *meshlink_main_loop(void *arg) {
	meshlink_handle_t *mesh = arg;

	if(mesh->netns != -1) {
#ifdef HAVE_SETNS

		if(setns(mesh->netns, CLONE_NEWNET) != 0) {
			pthread_cond_signal(&mesh->cond);
			return NULL;
		}

#else
		pthread_cond_signal(&mesh->cond);
		return NULL;
#endif // HAVE_SETNS
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	logger(mesh, MESHLINK_DEBUG, "Starting main_loop...\n");
	pthread_cond_broadcast(&mesh->cond);
	main_loop(mesh);
	logger(mesh, MESHLINK_DEBUG, "main_loop returned.\n");

	pthread_mutex_unlock(&mesh->mutex);

	return NULL;
}

bool meshlink_start(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "meshlink_start called\n");

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	assert(mesh->self);
	assert(mesh->private_key);
	assert(mesh->self->ecdsa);
	assert(!memcmp((uint8_t *)mesh->self->ecdsa + 64, (uint8_t *)mesh->private_key + 64, 32));

	if(mesh->threadstarted) {
		logger(mesh, MESHLINK_DEBUG, "thread was already running\n");
		pthread_mutex_unlock(&mesh->mutex);
		return true;
	}

	// Reset node connection timers
	if(mesh->peer) {
		mesh->peer->last_connect_try = 0;
	}

	//Check that a valid name is set
	if(!mesh->name) {
		logger(mesh, MESHLINK_ERROR, "No name given!\n");
		meshlink_errno = MESHLINK_EINVAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	init_outgoings(mesh);

	// Start the main thread

	event_loop_start(&mesh->loop);

	// Ensure we have a decent amount of stack space. Musl's default of 80 kB is too small.
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 1024 * 1024);

	if(pthread_create(&mesh->thread, &attr, meshlink_main_loop, mesh) != 0) {
		logger(mesh, MESHLINK_ERROR, "Could not start thread: %s\n", strerror(errno));
		memset(&mesh->thread, 0, sizeof(mesh)->thread);
		meshlink_errno = MESHLINK_EINTERNAL;
		event_loop_stop(&mesh->loop);
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	pthread_cond_wait(&mesh->cond, &mesh->mutex);
	mesh->threadstarted = true;

	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

void meshlink_stop(meshlink_handle_t *mesh) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_stop()\n");

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	// Shut down the main thread
	event_loop_stop(&mesh->loop);

	// TODO: send something to a local socket to kick the event loop

	if(mesh->threadstarted) {
		// Wait for the main thread to finish
		pthread_mutex_unlock(&mesh->mutex);

		if(pthread_join(mesh->thread, NULL) != 0) {
			abort();
		}

		if(pthread_mutex_lock(&mesh->mutex) != 0) {
			abort();
		}

		mesh->threadstarted = false;
	}

	// Close all metaconnections
	if(mesh->connection) {
		mesh->connection->outgoing = NULL;
		terminate_connection(mesh, mesh->connection, false);
	}

	exit_outgoings(mesh);

	// Try to write out any changed node config files, ignore errors at this point.
	if(mesh->peer && mesh->peer->status.dirty) {
		if(!node_write_config(mesh, mesh->peer, false)) {
			// ignore
		}
	}

	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_close(meshlink_handle_t *mesh) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_close()\n");

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	// stop can be called even if mesh has not been started
	meshlink_stop(mesh);

	// lock is not released after this
	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	// Close and free all resources used.

	close_network_connections(mesh);

	logger(mesh, MESHLINK_INFO, "Terminating");

	event_loop_exit(&mesh->loop);

#ifdef HAVE_MINGW

	if(mesh->confbase) {
		WSACleanup();
	}

#endif

	if(mesh->netns != -1) {
		close(mesh->netns);
	}

	for(vpn_packet_t *packet; (packet = meshlink_queue_pop(&mesh->outpacketqueue));) {
		free(packet);
	}

	meshlink_queue_exit(&mesh->outpacketqueue);

	free(mesh->name);
	free(mesh->appname);
	free(mesh->confbase);
	free(mesh->config_key);
	free(mesh->external_address_url);
	free(mesh->packet);
	ecdsa_free(mesh->private_key);

	main_config_unlock(mesh);

	pthread_mutex_unlock(&mesh->mutex);
	pthread_mutex_destroy(&mesh->mutex);

	memset(mesh, 0, sizeof(*mesh));

	free(mesh);
}

bool meshlink_destroy_ex(const meshlink_open_params_t *params) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_destroy_ex()\n");

	if(!params) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(!params->confbase) {
		/* Ephemeral instances */
		return true;
	}

	/* Exit early if the confbase directory itself doesn't exist */
	if(access(params->confbase, F_OK) && errno == ENOENT) {
		return true;
	}

	/* Take the lock the same way meshlink_open() would. */
	FILE *lockfile = fopen(params->lock_filename, "w+");

	if(!lockfile) {
		logger(NULL, MESHLINK_ERROR, "Could not open lock file %s: %s", params->lock_filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(fileno(lockfile), F_SETFD, FD_CLOEXEC);
#endif

#ifdef HAVE_MINGW
	// TODO: use _locking()?
#else

	if(flock(fileno(lockfile), LOCK_EX | LOCK_NB) != 0) {
		logger(NULL, MESHLINK_ERROR, "Configuration directory %s still in use\n", params->lock_filename);
		fclose(lockfile);
		meshlink_errno = MESHLINK_EBUSY;
		return false;
	}

#endif

	if(!config_destroy(params->confbase, "current") || !config_destroy(params->confbase, "new") || !config_destroy(params->confbase, "old")) {
		logger(NULL, MESHLINK_ERROR, "Cannot remove sub-directories in %s: %s\n", params->confbase, strerror(errno));
		return false;
	}

	if(unlink(params->lock_filename)) {
		logger(NULL, MESHLINK_ERROR, "Cannot remove lock file %s: %s\n", params->lock_filename, strerror(errno));
		fclose(lockfile);
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	fclose(lockfile);

	if(!sync_path(params->confbase)) {
		logger(NULL, MESHLINK_ERROR, "Cannot sync directory %s: %s\n", params->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

bool meshlink_destroy(const char *confbase) {
	logger(NULL, MESHLINK_DEBUG, "meshlink_destroy(%s)", confbase);

	char lock_filename[PATH_MAX];
	snprintf(lock_filename, sizeof(lock_filename), "%s" SLASH "meshlink.lock", confbase);

	meshlink_open_params_t params = {
		.confbase = (char *)confbase,
		.lock_filename = lock_filename,
	};

	return meshlink_destroy_ex(&params);
}

void meshlink_set_receive_cb(meshlink_handle_t *mesh, meshlink_receive_cb_t cb) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_receive_cb(%p)", (void *)(intptr_t)cb);

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->receive_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_connection_try_cb(meshlink_handle_t *mesh, meshlink_connection_try_cb_t cb) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_connection_try_cb(%p)", (void *)(intptr_t)cb);

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->connection_try_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_node_status_cb(meshlink_handle_t *mesh, meshlink_node_status_cb_t cb) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_node_status_cb(%p)", (void *)(intptr_t)cb);

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->node_status_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_node_duplicate_cb(meshlink_handle_t *mesh, meshlink_node_duplicate_cb_t cb) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_node_duplicate_cb(%p)", (void *)(intptr_t)cb);

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->node_duplicate_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_log_cb(meshlink_handle_t *mesh, meshlink_log_level_t level, meshlink_log_cb_t cb) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_log_cb(%p)", (void *)(intptr_t)cb);

	if(mesh) {
		if(pthread_mutex_lock(&mesh->mutex) != 0) {
			abort();
		}

		mesh->log_cb = cb;
		mesh->log_level = cb ? level : 0;
		pthread_mutex_unlock(&mesh->mutex);
	} else {
		global_log_cb = cb;
		global_log_level = cb ? level : 0;
	}
}

void meshlink_set_error_cb(struct meshlink_handle *mesh, meshlink_error_cb_t cb) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_error_cb(%p)", (void *)(intptr_t)cb);

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->error_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}

bool meshlink_send(meshlink_handle_t *mesh, meshlink_node_t *destination, const void *data, size_t len) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_send(%s, %p, %zu)", destination ? destination->name : "(null)", data, len);

	// Validate arguments
	if(!mesh || !destination) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(!len) {
		return true;
	}

	if(!data || len > MTU) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	// Prepare the packet
	vpn_packet_t *packet = malloc(sizeof(*packet));

	if(!packet) {
		meshlink_errno = MESHLINK_ENOMEM;
		return false;
	}

	packet->len = len;
	memcpy(packet->data, data, len);

	// Queue it
	if(!meshlink_queue_push(&mesh->outpacketqueue, packet)) {
		free(packet);
		meshlink_errno = MESHLINK_ENOMEM;
		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "Adding packet of %zu bytes to packet queue", len);

	// Notify event loop
	signal_trigger(&mesh->loop, &mesh->datafromapp);

	return true;
}

void meshlink_send_from_queue(event_loop_t *loop, void *data) {
	(void)loop;
	meshlink_handle_t *mesh = data;

	logger(mesh, MESHLINK_DEBUG, "Flushing the packet queue");

	for(vpn_packet_t *packet; (packet = meshlink_queue_pop(&mesh->outpacketqueue));) {
		logger(mesh, MESHLINK_DEBUG, "Removing packet of %d bytes from packet queue", packet->len);
		send_raw_packet(mesh, mesh->peer->connection, packet);
		free(packet);
	}
}

char *meshlink_get_fingerprint(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;

	if(!node_read_public_key(mesh, n) || !n->ecdsa) {
		meshlink_errno = MESHLINK_EINTERNAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	char *fingerprint = ecdsa_get_base64_public_key(n->ecdsa);

	if(!fingerprint) {
		meshlink_errno = MESHLINK_EINTERNAL;
	}

	pthread_mutex_unlock(&mesh->mutex);
	return fingerprint;
}

meshlink_node_t *meshlink_get_self(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	return (meshlink_node_t *)mesh->self;
}

meshlink_node_t *meshlink_get_node(meshlink_handle_t *mesh, const char *name) {
	if(!mesh || !name) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	node_t *n = NULL;

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	n = lookup_node(mesh, (char *)name); // TODO: make lookup_node() use const
	pthread_mutex_unlock(&mesh->mutex);

	if(!n) {
		meshlink_errno = MESHLINK_ENOENT;
	}

	return (meshlink_node_t *)n;
}

bool meshlink_sign(meshlink_handle_t *mesh, const void *data, size_t len, void *signature, size_t *siglen) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_sign(%p, %zu, %p, %p)", data, len, signature, (void *)siglen);

	if(!mesh || !data || !len || !signature || !siglen) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(*siglen < MESHLINK_SIGLEN) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	if(!ecdsa_sign(mesh->private_key, data, len, signature)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	*siglen = MESHLINK_SIGLEN;
	pthread_mutex_unlock(&mesh->mutex);
	return true;
}

bool meshlink_verify(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len, const void *signature, size_t siglen) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_verify(%p, %zu, %p, %zu)", data, len, signature, siglen);

	if(!mesh || !source || !data || !len || !signature) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(siglen != MESHLINK_SIGLEN) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	bool rval = false;

	struct node_t *n = (struct node_t *)source;

	if(!node_read_public_key(mesh, n)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		rval = false;
	} else {
		rval = ecdsa_verify(((struct node_t *)source)->ecdsa, data, len, signature);
	}

	pthread_mutex_unlock(&mesh->mutex);
	return rval;
}

bool meshlink_set_canonical_address(meshlink_handle_t *mesh, meshlink_node_t *node, const char *address, const char *port) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_canonical_address(%s, %s, %s)", node ? node->name : "(null)", address ? address : "(null)", port ? port : "(null)");

	if(!mesh || !node || !address) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(!is_valid_hostname(address)) {
		logger(mesh, MESHLINK_ERROR, "Invalid character in address: %s", address);
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if((node_t *)node != mesh->self && !port) {
		logger(mesh, MESHLINK_ERROR, "Missing port number!");
		meshlink_errno = MESHLINK_EINVAL;
		return false;

	}

	if(port && !is_valid_port(port)) {
		logger(mesh, MESHLINK_ERROR, "Invalid character in port: %s", address);
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	char *canonical_address;

	xasprintf(&canonical_address, "%s %s", address, port ? port : mesh->myport);

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	free(n->canonical_address);
	n->canonical_address = canonical_address;

	if(!node_write_config(mesh, n, false)) {
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	pthread_mutex_unlock(&mesh->mutex);

	return config_sync(mesh, "current");
}

bool meshlink_clear_canonical_address(meshlink_handle_t *mesh, meshlink_node_t *node) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_clear_canonical_address(%s)", node ? node->name : "(null)");

	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;
	free(n->canonical_address);
	n->canonical_address = NULL;

	if(!node_write_config(mesh, n, false)) {
		pthread_mutex_unlock(&mesh->mutex);
		return false;
	}

	pthread_mutex_unlock(&mesh->mutex);

	return config_sync(mesh, "current");
}

bool meshlink_join(meshlink_handle_t *mesh, const char *invitation) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_join(%s)", invitation ? invitation : "(null)");

	if(!mesh || !invitation) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	if(mesh->storage_policy == MESHLINK_STORAGE_DISABLED) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	join_state_t state = {
		.mesh = mesh,
		.sock = -1,
	};

	ecdsa_t *key = NULL;
	ecdsa_t *hiskey = NULL;

	//TODO: think of a better name for this variable, or of a different way to tokenize the invitation URL.
	char copy[strlen(invitation) + 1];

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	//Before doing meshlink_join make sure we are not connected to another mesh
	if(mesh->threadstarted) {
		logger(mesh, MESHLINK_ERROR, "Cannot join while started\n");
		meshlink_errno = MESHLINK_EINVAL;
		goto exit;
	}

	// Refuse to join a mesh if we are already part of one. We are part of one if we know at least one other node.
	if(mesh->peer) {
		logger(mesh, MESHLINK_ERROR, "Already part of an existing mesh\n");
		meshlink_errno = MESHLINK_EINVAL;
		goto exit;
	}

	strcpy(copy, invitation);

	// Split the invitation URL into a list of hostname/port tuples, a key hash and a cookie.

	char *slash = strchr(copy, '/');

	if(!slash) {
		goto invalid;
	}

	*slash++ = 0;

	if(strlen(slash) != 48) {
		goto invalid;
	}

	char *address = copy;
	char *port = NULL;

	if(!b64decode(slash, state.hash, 18) || !b64decode(slash + 24, state.cookie, 18)) {
		goto invalid;
	}

	if(mesh->inviter_commits_first) {
		memcpy(state.cookie + 18, ecdsa_get_public_key(mesh->private_key), 32);
	}

	// Generate a throw-away key for the invitation.
	key = ecdsa_generate();

	if(!key) {
		meshlink_errno = MESHLINK_EINTERNAL;
		goto exit;
	}

	char *b64key = ecdsa_get_base64_public_key(key);
	char *comma;

	while(address && *address) {
		// We allow commas in the address part to support multiple addresses in one invitation URL.
		comma = strchr(address, ',');

		if(comma) {
			*comma++ = 0;
		}

		// Split of the port
		port = strrchr(address, ':');

		if(!port) {
			goto invalid;
		}

		*port++ = 0;

		// IPv6 address are enclosed in brackets, per RFC 3986
		if(*address == '[') {
			address++;
			char *bracket = strchr(address, ']');

			if(!bracket) {
				goto invalid;
			}

			*bracket++ = 0;

			if(*bracket) {
				goto invalid;
			}
		}

		// Connect to the meshlink daemon mentioned in the URL.
		struct addrinfo *ai = str2addrinfo(address, port, SOCK_STREAM);

		if(ai) {
			for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
				state.sock = socket_in_netns(aip->ai_family, SOCK_STREAM, IPPROTO_TCP, mesh->netns);

				if(state.sock == -1) {
					logger(mesh, MESHLINK_DEBUG, "Could not open socket: %s\n", strerror(errno));
					meshlink_errno = MESHLINK_ENETWORK;
					continue;
				}

#ifdef SO_NOSIGPIPE
				int nosigpipe = 1;
				setsockopt(state.sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

				set_timeout(state.sock, 5000);

				if(connect(state.sock, aip->ai_addr, aip->ai_addrlen)) {
					logger(mesh, MESHLINK_DEBUG, "Could not connect to %s port %s: %s\n", address, port, strerror(errno));
					meshlink_errno = MESHLINK_ENETWORK;
					closesocket(state.sock);
					state.sock = -1;
					continue;
				}

				break;
			}

			freeaddrinfo(ai);
		} else {
			meshlink_errno = MESHLINK_ERESOLV;
		}

		if(state.sock != -1 || !comma) {
			break;
		}

		address = comma;
	}

	if(state.sock == -1) {
		goto exit;
	}

	logger(mesh, MESHLINK_DEBUG, "Connected to %s port %s...\n", address, port);

	// Tell him we have an invitation, and give him our throw-away key.

	state.blen = 0;

	if(!sendline(state.sock, "0 ?%s %d.%d %s", b64key, PROT_MAJOR, PROT_MINOR, mesh->appname)) {
		logger(mesh, MESHLINK_ERROR, "Error sending request to %s port %s: %s\n", address, port, strerror(errno));
		meshlink_errno = MESHLINK_ENETWORK;
		goto exit;
	}

	free(b64key);

	char hisname[4096] = "";
	int code, hismajor, hisminor = 0;

	if(!recvline(&state) || sscanf(state.line, "%d %s %d.%d", &code, hisname, &hismajor, &hisminor) < 3 || code != 0 || hismajor != PROT_MAJOR || !check_id(hisname) || !recvline(&state) || !rstrip(state.line) || sscanf(state.line, "%d ", &code) != 1 || code != ACK || strlen(state.line) < 3) {
		logger(mesh, MESHLINK_ERROR, "Cannot read greeting from peer\n");
		meshlink_errno = MESHLINK_ENETWORK;
		goto exit;
	}

	// Check if the hash of the key he gave us matches the hash in the URL.
	char *fingerprint = state.line + 2;
	char hishash[64];

	if(sha512(fingerprint, strlen(fingerprint), hishash)) {
		logger(mesh, MESHLINK_ERROR, "Could not create hash\n%s\n", state.line + 2);
		meshlink_errno = MESHLINK_EINTERNAL;
		goto exit;
	}

	if(memcmp(hishash, state.hash, 18)) {
		logger(mesh, MESHLINK_ERROR, "Peer has an invalid key!\n%s\n", state.line + 2);
		meshlink_errno = MESHLINK_EPEER;
		goto exit;
	}

	hiskey = ecdsa_set_base64_public_key(fingerprint);

	if(!hiskey) {
		meshlink_errno = MESHLINK_EINTERNAL;
		goto exit;
	}

	// Start an SPTPS session
	if(!sptps_start(&state.sptps, &state, true, false, key, hiskey, meshlink_invitation_label, sizeof(meshlink_invitation_label), invitation_send, invitation_receive)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		goto exit;
	}

	// Feed rest of input buffer to SPTPS
	if(!sptps_receive_data(&state.sptps, state.buffer, state.blen)) {
		meshlink_errno = MESHLINK_EPEER;
		goto exit;
	}

	ssize_t len;
	logger(mesh, MESHLINK_DEBUG, "Starting invitation recv loop: %d %zu\n", state.sock, sizeof(state.line));

	while((len = recv(state.sock, state.line, sizeof(state.line), 0))) {
		if(len < 0) {
			if(errno == EINTR) {
				continue;
			}

			logger(mesh, MESHLINK_ERROR, "Error reading data from %s port %s: %s\n", address, port, strerror(errno));
			meshlink_errno = MESHLINK_ENETWORK;
			goto exit;
		}

		if(!sptps_receive_data(&state.sptps, state.line, len)) {
			meshlink_errno = MESHLINK_EPEER;
			goto exit;
		}
	}

	if(!state.success) {
		logger(mesh, MESHLINK_ERROR, "Connection closed by peer, invitation cancelled.\n");
		meshlink_errno = MESHLINK_EPEER;
		goto exit;
	}

	sptps_stop(&state.sptps);
	ecdsa_free(hiskey);
	ecdsa_free(key);
	closesocket(state.sock);

	pthread_mutex_unlock(&mesh->mutex);
	return true;

invalid:
	logger(mesh, MESHLINK_ERROR, "Invalid invitation URL\n");
	meshlink_errno = MESHLINK_EINVAL;
exit:
	sptps_stop(&state.sptps);
	ecdsa_free(hiskey);
	ecdsa_free(key);

	if(state.sock != -1) {
		closesocket(state.sock);
	}

	pthread_mutex_unlock(&mesh->mutex);
	return false;
}

char *meshlink_export(meshlink_handle_t *mesh) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	// Create a config file on the fly.

	uint8_t buf[4096];
	packmsg_output_t out = {buf, sizeof(buf)};
	packmsg_add_uint32(&out, MESHLINK_CONFIG_VERSION);
	packmsg_add_str(&out, mesh->name);
	packmsg_add_str(&out, CORE_MESH);

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	packmsg_add_int32(&out, mesh->self->devclass);
	packmsg_add_bool(&out, mesh->self->status.blacklisted);
	packmsg_add_bin(&out, ecdsa_get_public_key(mesh->private_key), 32);

	if(mesh->self->canonical_address && !strchr(mesh->self->canonical_address, ' ')) {
		char *canonical_address = NULL;
		xasprintf(&canonical_address, "%s %s", mesh->self->canonical_address, mesh->myport);
		packmsg_add_str(&out, canonical_address);
		free(canonical_address);
	} else {
		packmsg_add_str(&out, mesh->self->canonical_address ? mesh->self->canonical_address : "");
	}

	uint32_t count = 0;

	for(uint32_t i = 0; i < MAX_RECENT; i++) {
		if(mesh->self->recent[i].sa.sa_family) {
			count++;
		} else {
			break;
		}
	}

	packmsg_add_array(&out, count);

	for(uint32_t i = 0; i < count; i++) {
		packmsg_add_sockaddr(&out, &mesh->self->recent[i]);
	}

	packmsg_add_int64(&out, 0);
	packmsg_add_int64(&out, 0);

	pthread_mutex_unlock(&mesh->mutex);

	if(!packmsg_output_ok(&out)) {
		logger(mesh, MESHLINK_ERROR, "Error creating export data\n");
		meshlink_errno = MESHLINK_EINTERNAL;
		return NULL;
	}

	// Prepare a base64-encoded packmsg array containing our config file

	uint32_t len = packmsg_output_size(&out, buf);
	uint32_t len2 = ((len + 4) * 4) / 3 + 4;
	uint8_t *buf2 = xmalloc(len2);
	packmsg_output_t out2 = {buf2, len2};
	packmsg_add_array(&out2, 1);
	packmsg_add_bin(&out2, buf, packmsg_output_size(&out, buf));

	if(!packmsg_output_ok(&out2)) {
		logger(mesh, MESHLINK_ERROR, "Error creating export data\n");
		meshlink_errno = MESHLINK_EINTERNAL;
		free(buf2);
		return NULL;
	}

	b64encode_urlsafe(buf2, (char *)buf2, packmsg_output_size(&out2, buf2));

	return (char *)buf2;
}

bool meshlink_import(meshlink_handle_t *mesh, const char *data) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_import(%p)", (const void *)data);

	if(!mesh || !data) {
		meshlink_errno = MESHLINK_EINVAL;
		return false;
	}

	size_t datalen = strlen(data);
	uint8_t *buf = xmalloc(datalen);
	int buflen = b64decode(data, buf, datalen);

	if(!buflen) {
		logger(mesh, MESHLINK_ERROR, "Invalid data\n");
		free(buf);
		meshlink_errno = MESHLINK_EPEER;
		return false;
	}

	packmsg_input_t in = {buf, buflen};
	uint32_t count = packmsg_get_array(&in);

	if(!count) {
		logger(mesh, MESHLINK_ERROR, "Invalid data\n");
		free(buf);
		meshlink_errno = MESHLINK_EPEER;
		return false;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	while(count--) {
		const void *data2;
		uint32_t len2 = packmsg_get_bin_raw(&in, &data2);

		if(!len2) {
			break;
		}

		packmsg_input_t in2 = {data2, len2};
		uint32_t version = packmsg_get_uint32(&in2);
		char *name = packmsg_get_str_dup(&in2);

		if(!packmsg_input_ok(&in2) || version != MESHLINK_CONFIG_VERSION || !check_id(name)) {
			free(name);
			packmsg_input_invalidate(&in);
			break;
		}

		if(!check_id(name)) {
			free(name);
			break;
		}

		node_t *n = lookup_node(mesh, name);

		if(n) {
			logger(mesh, MESHLINK_DEBUG, "Node %s already exists, not importing\n", name);
			free(name);
			continue;
		}

		n = new_node();
		n->name = name;

		config_t config = {data2, len2};

		if(!node_read_from_config(mesh, n, &config)) {
			free_node(n);
			packmsg_input_invalidate(&in);
			break;
		}

		if(!node_write_config(mesh, n, true)) {
			free_node(n);
			free(buf);
			return false;
		}

		node_add(mesh, n);
	}

	pthread_mutex_unlock(&mesh->mutex);

	free(buf);

	if(!packmsg_done(&in)) {
		logger(mesh, MESHLINK_ERROR, "Invalid data\n");
		meshlink_errno = MESHLINK_EPEER;
		return false;
	}

	if(!config_sync(mesh, "current")) {
		return false;
	}

	return true;
}

/* Hint that a hostname may be found at an address
 * See header file for detailed comment.
 */
void meshlink_hint_address(meshlink_handle_t *mesh, meshlink_node_t *node, const struct sockaddr *addr) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_hint_address(%s, %p)", node ? node->name : "(null)", (const void *)addr);

	if(!mesh || !node || !addr) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	node_t *n = (node_t *)node;

	if(node_add_recent_address(mesh, n, (sockaddr_t *)addr)) {
		if(!node_write_config(mesh, n, false)) {
			logger(mesh, MESHLINK_DEBUG, "Could not update %s\n", n->name);
		}
	}

	pthread_mutex_unlock(&mesh->mutex);
	// @TODO do we want to fire off a connection attempt right away?
}

void update_node_status(meshlink_handle_t *mesh, node_t *n) {
	if(mesh->node_status_cb) {
		mesh->node_status_cb(mesh, (meshlink_node_t *)n, n->status.reachable && !n->status.blacklisted);
	}
}

void handle_duplicate_node(meshlink_handle_t *mesh, node_t *n) {
	if(!mesh->node_duplicate_cb || n->status.duplicate) {
		return;
	}

	n->status.duplicate = true;
	mesh->node_duplicate_cb(mesh, (meshlink_node_t *)n);
}

void meshlink_hint_network_change(struct meshlink_handle *mesh) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_hint_network_change()");

	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_dev_class_timeouts(meshlink_handle_t *mesh, dev_class_t devclass, int pinginterval, int pingtimeout) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_dev_class_timeouts(%d, %d, %d)", devclass, pinginterval, pingtimeout);

	if(!mesh || devclass < 0 || devclass >= DEV_CLASS_COUNT) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pinginterval < 1 || pingtimeout < 1 || pingtimeout > pinginterval) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->dev_class_traits[devclass].pinginterval = pinginterval;
	mesh->dev_class_traits[devclass].pingtimeout = pingtimeout;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_dev_class_fast_retry_period(meshlink_handle_t *mesh, dev_class_t devclass, int fast_retry_period) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_dev_class_fast_retry_period(%d, %d)", devclass, fast_retry_period);

	if(!mesh || devclass < 0 || devclass >= DEV_CLASS_COUNT) {
		meshlink_errno = EINVAL;
		return;
	}

	if(fast_retry_period < 0) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->dev_class_traits[devclass].fast_retry_period = fast_retry_period;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_dev_class_maxtimeout(struct meshlink_handle *mesh, dev_class_t devclass, int maxtimeout) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_dev_class_fast_maxtimeout(%d, %d)", devclass, maxtimeout);

	if(!mesh || devclass < 0 || devclass >= DEV_CLASS_COUNT) {
		meshlink_errno = EINVAL;
		return;
	}

	if(maxtimeout < 0) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->dev_class_traits[devclass].maxtimeout = maxtimeout;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_reset_timers(struct meshlink_handle *mesh) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_reset_timers()");

	if(!mesh) {
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	handle_network_change(mesh, true);

	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_inviter_commits_first(struct meshlink_handle *mesh, bool inviter_commits_first) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_inviter_commits_first(%d)", inviter_commits_first);

	if(!mesh) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->inviter_commits_first = inviter_commits_first;
	pthread_mutex_unlock(&mesh->mutex);
}

void meshlink_set_storage_policy(struct meshlink_handle *mesh, meshlink_storage_policy_t policy) {
	logger(mesh, MESHLINK_DEBUG, "meshlink_set_storage_policy(%d)", policy);

	if(!mesh) {
		meshlink_errno = EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->storage_policy = policy;
	pthread_mutex_unlock(&mesh->mutex);
}

void handle_network_change(meshlink_handle_t *mesh, bool online) {
	(void)online;

	if(!mesh->loop.running) {
		return;
	}

	retry(mesh);
	signal_trigger(&mesh->loop, &mesh->datafromapp);
}

void call_error_cb(meshlink_handle_t *mesh, meshlink_errno_t cb_errno) {
	// We should only call the callback function if we are in the background thread.
	if(!mesh->error_cb) {
		return;
	}

	if(!mesh->threadstarted) {
		return;
	}

	if(mesh->thread == pthread_self()) {
		mesh->error_cb(mesh, cb_errno);
	}
}

static void __attribute__((constructor)) meshlink_init(void) {
	crypto_init();
}

static void __attribute__((destructor)) meshlink_exit(void) {
	crypto_exit();
}
