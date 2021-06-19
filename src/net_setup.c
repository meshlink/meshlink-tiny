/*
    net_setup.c -- Setup.
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>

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

#include "conf.h"
#include "connection.h"
#include "ecdsa.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "packmsg.h"
#include "protocol.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

/// Helper function to start parsing a host config file
static bool node_get_config(meshlink_handle_t *mesh, node_t *n, config_t *config, packmsg_input_t *in) {
	if(!config_read(mesh, "current", n->name, config, mesh->config_key)) {
		return false;
	}

	in->ptr = config->buf;
	in->len = config->len;

	uint32_t version = packmsg_get_uint32(in);

	if(version != MESHLINK_CONFIG_VERSION) {
		logger(mesh, MESHLINK_ERROR, "Invalid config file for node %s", n->name);
		config_free(config);
		return false;
	}

	const char *name;
	uint32_t len = packmsg_get_str_raw(in, &name);

	if(len != strlen(n->name) || !name || strncmp(name, n->name, len)) {
		logger(mesh, MESHLINK_ERROR, "Invalid config file for node %s", n->name);
		config_free(config);
		return false;
	}

	return true;
}

/// Read the public key from a host config file. Used whenever we need to start an SPTPS session.
bool node_read_public_key(meshlink_handle_t *mesh, node_t *n) {
	if(ecdsa_active(n->ecdsa)) {
		return true;
	}

	config_t config;
	packmsg_input_t in;

	if(!node_get_config(mesh, n, &config, &in)) {
		return false;
	}

	packmsg_skip_element(&in); /* submesh */
	packmsg_get_int32(&in); /* devclass */
	packmsg_get_bool(&in); /* blacklisted */

	const void *key;
	uint32_t len = packmsg_get_bin_raw(&in, &key);

	if(len != 32) {
		config_free(&config);
		return false;
	}

	n->ecdsa = ecdsa_set_public_key(key);

	// While we are at it, read known address information
	if(!n->canonical_address) {
		n->canonical_address = packmsg_get_str_dup(&in);

		if(!*n->canonical_address) {
			free(n->canonical_address);
			n->canonical_address = NULL;
		}
	} else {
		packmsg_skip_element(&in);
	}

	// Append any known addresses in the config file to the list we currently have
	uint32_t known_count = 0;

	for(uint32_t i = 0; i < MAX_RECENT; i++) {
		if(n->recent[i].sa.sa_family) {
			known_count++;
		}
	}

	uint32_t count = packmsg_get_array(&in);

	for(uint32_t i = 0; i < count; i++) {
		if(i < MAX_RECENT - known_count) {
			n->recent[i + known_count] = packmsg_get_sockaddr(&in);
		} else {
			packmsg_skip_element(&in);
		}
	}

	packmsg_skip_element(&in); // last_reachable
	packmsg_skip_element(&in); // last_unreachable

	config_free(&config);
	return true;
}

/// Fill in node details from a config blob.
bool node_read_from_config(meshlink_handle_t *mesh, node_t *n, const config_t *config) {
	(void)mesh;

	if(n->canonical_address) {
		return true;
	}

	packmsg_input_t in = {config->buf, config->len};
	uint32_t version = packmsg_get_uint32(&in);

	if(version != MESHLINK_CONFIG_VERSION) {
		return false;
	}

	char *name = packmsg_get_str_dup(&in);

	if(!name) {
		return false;
	}

	if(n->name) {
		if(strcmp(n->name, name)) {
			free(name);
			return false;
		}

		free(name);
	} else {
		n->name = name;
	}

	packmsg_skip_element(&in); // submesh_name

	n->devclass = packmsg_get_int32(&in);
	n->status.blacklisted = packmsg_get_bool(&in);
	const void *key;
	uint32_t len = packmsg_get_bin_raw(&in, &key);

	if(len) {
		if(len != 32) {
			return false;
		}

		if(!ecdsa_active(n->ecdsa)) {
			n->ecdsa = ecdsa_set_public_key(key);
		}
	}

	n->canonical_address = packmsg_get_str_dup(&in);

	if(!*n->canonical_address) {
		free(n->canonical_address);
		n->canonical_address = NULL;
	}

	uint32_t count = packmsg_get_array(&in);

	for(uint32_t i = 0; i < count; i++) {
		if(i < MAX_RECENT) {
			n->recent[i] = packmsg_get_sockaddr(&in);
		} else {
			packmsg_skip_element(&in);
		}
	}

	packmsg_skip_element(&in); // last_reachable
	packmsg_skip_element(&in); // last_unreachable

	return packmsg_done(&in);
}

bool node_write_config(meshlink_handle_t *mesh, node_t *n, bool new_key) {
	if(!mesh->confbase) {
		return true;
	}

	switch(mesh->storage_policy) {
	case MESHLINK_STORAGE_KEYS_ONLY:
		if(!new_key) {
			return true;
		}

		break;

	case MESHLINK_STORAGE_DISABLED:
		return true;

	default:
		break;
	}

	uint8_t buf[4096];
	packmsg_output_t out = {buf, sizeof(buf)};

	packmsg_add_uint32(&out, MESHLINK_CONFIG_VERSION);
	packmsg_add_str(&out, n->name);
	packmsg_add_str(&out, CORE_MESH);
	packmsg_add_int32(&out, n->devclass);
	packmsg_add_bool(&out, n->status.blacklisted);

	if(ecdsa_active(n->ecdsa)) {
		packmsg_add_bin(&out, ecdsa_get_public_key(n->ecdsa), 32);
	} else {
		packmsg_add_bin(&out, "", 0);
	}

	packmsg_add_str(&out, n->canonical_address ? n->canonical_address : "");

	uint32_t count = 0;

	for(uint32_t i = 0; i < MAX_RECENT; i++) {
		if(n->recent[i].sa.sa_family) {
			count++;
		} else {
			break;
		}
	}

	packmsg_add_array(&out, count);

	for(uint32_t i = 0; i < count; i++) {
		packmsg_add_sockaddr(&out, &n->recent[i]);
	}

	packmsg_add_int64(&out, 0); // last_reachable
	packmsg_add_int64(&out, 0); // last_unreachable

	if(!packmsg_output_ok(&out)) {
		meshlink_errno = MESHLINK_EINTERNAL;
		return false;
	}

	config_t config = {buf, packmsg_output_size(&out, buf)};

	if(!config_write(mesh, "current", n->name, &config, mesh->config_key)) {
		call_error_cb(mesh, MESHLINK_ESTORAGE);
		return false;
	}

	n->status.dirty = false;
	return true;
}

static bool load_node(meshlink_handle_t *mesh, const char *name, void *priv) {
	(void)priv;

	if(!check_id(name)) {
		// Check if this is a temporary file, if so remove it
		const char *suffix = strstr(name, ".tmp");

		if(suffix && !suffix[4]) {
			char filename[PATH_MAX];
			snprintf(filename, sizeof(filename), "%s" SLASH "current" SLASH "hosts", mesh->confbase);
			unlink(filename);
		}

		return true;
	}

	node_t *n = lookup_node(mesh, name);

	if(n) {
		return true;
	}

	n = new_node();
	n->name = xstrdup(name);

	config_t config;
	packmsg_input_t in;

	if(!node_get_config(mesh, n, &config, &in)) {
		free_node(n);
		return false;
	}

	if(!node_read_from_config(mesh, n, &config)) {
		logger(mesh, MESHLINK_ERROR, "Invalid config file for node %s", n->name);
		config_free(&config);
		free_node(n);
		return false;
	}

	config_free(&config);

	node_add(mesh, n);

	return true;
}

/*
  Configure node_t mesh->self and set up the local sockets (listen only)
*/
static bool setup_myself(meshlink_handle_t *mesh) {
	mesh->self->nexthop = mesh->self;

	node_add(mesh, mesh->self);

	if(!config_scan_all(mesh, "current", "hosts", load_node, NULL)) {
		logger(mesh, MESHLINK_WARNING, "Could not scan all host config files");
	}

	/* Done. */

	mesh->last_unreachable = mesh->loop.now.tv_sec;

	return true;
}

/*
  initialize network
*/
bool setup_network(meshlink_handle_t *mesh) {
	init_connections(mesh);
	init_nodes(mesh);
	init_requests(mesh);

	if(!setup_myself(mesh)) {
		return false;
	}

	return true;
}

/*
  close all open network connections
*/
void close_network_connections(meshlink_handle_t *mesh) {
	if(mesh->connections) {
		for(list_node_t *node = mesh->connections->head, *next; node; node = next) {
			next = node->next;
			connection_t *c = node->data;
			c->outgoing = NULL;
			terminate_connection(mesh, c, false);
		}
	}

	exit_requests(mesh);
	exit_nodes(mesh);
	exit_connections(mesh);

	free(mesh->myport);
	mesh->myport = NULL;

	mesh->self = NULL;

	return;
}
