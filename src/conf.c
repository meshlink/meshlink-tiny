/*
    econf.c -- configuration code
    Copyright (C) 2018 Guus Sliepen <guus@meshlink.io>

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

#include <assert.h>
#include <sys/types.h>
#include <utime.h>

#include "conf.h"
#include "crypto.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "packmsg.h"
#include "protocol.h"
#include "xalloc.h"

static bool sync_path(const char *pathname) {
	assert(pathname);

	int fd = open(pathname, O_RDONLY);

	if(fd < 0) {
		logger(NULL, MESHLINK_ERROR, "Failed to open %s: %s\n", pathname, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(fsync(fd)) {
		logger(NULL, MESHLINK_ERROR, "Failed to sync %s: %s\n", pathname, strerror(errno));
		close(fd);
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(close(fd)) {
		logger(NULL, MESHLINK_ERROR, "Failed to close %s: %s\n", pathname, strerror(errno));
		close(fd);
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

static bool invalidate_config_file(meshlink_handle_t *mesh, const char *name, size_t len) {
	(void)len;
	config_t empty_config = {NULL, 0};
	return config_store(mesh, name, &empty_config);
}

/// Wipe an existing configuration directory
bool config_destroy(const struct meshlink_open_params *params) {
	if(!params->confbase) {
		return true;
	}

	FILE *lockfile = NULL;

	if(!params->load_cb) {
		/* Exit early if the confbase directory itself doesn't exist */
		if(access(params->confbase, F_OK) && errno == ENOENT) {
			return true;
		}

		/* Take the lock the same way meshlink_open() would. */
		lockfile = fopen(params->lock_filename, "w+");

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
	}

	{
		meshlink_handle_t tmp_mesh;
		memset(&tmp_mesh, 0, sizeof tmp_mesh);

		tmp_mesh.confbase = params->confbase;
		tmp_mesh.name = params->name;
		tmp_mesh.load_cb = params->load_cb;
		tmp_mesh.store_cb = params->store_cb;
		tmp_mesh.ls_cb = params->ls_cb;

		if(!config_ls(&tmp_mesh, invalidate_config_file)) {
			logger(NULL, MESHLINK_ERROR, "Cannot remove configuration files\n");
			fclose(lockfile);
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}
	}

	if(!params->load_cb) {
		if(unlink(params->lock_filename) && errno != ENOENT) {
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

		rmdir(params->confbase);
	}

	return true;
}

/// Read a blob of data.
static bool load(meshlink_handle_t *mesh, const char *key, void *data, size_t *len) {
	logger(mesh, MESHLINK_DEBUG, "load(%s, %p, %zu)", key ? key : "(null)", data, *len);

	if(mesh->load_cb) {
		if(!mesh->load_cb(mesh, key, data, len)) {
			logger(mesh, MESHLINK_ERROR, "Failed to open `%s'\n", key);
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		} else {
			return true;
		}
	}

	char filename[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s/%s", mesh->confbase, key);

	FILE *f = fopen(filename, "r");

	if(!f) {
		logger(mesh, MESHLINK_ERROR, "Failed to open `%s': %s\n", filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	long actual_len;

	if(fseek(f, 0, SEEK_END) || (actual_len = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET)) {
		logger(mesh, MESHLINK_ERROR, "Cannot get config file size: %s\n", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		fclose(f);
		return false;
	}

	size_t todo = (size_t)actual_len < *len ? (size_t)actual_len : *len;
	*len = actual_len;

	if(!data) {
		fclose(f);
		return true;
	}

	if(fread(data, todo, 1, f) != 1) {
		logger(mesh, MESHLINK_ERROR, "Cannot read config file: %s\n", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		fclose(f);
		return false;
	}

	if(fclose(f)) {
		logger(mesh, MESHLINK_ERROR, "Failed to close `%s': %s", filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Store a blob of data.
static bool store(meshlink_handle_t *mesh, const char *key, const void *data, size_t len) {
	logger(mesh, MESHLINK_DEBUG, "store(%s, %p, %zu)", key ? key : "(null)", data, len);

	if(mesh->store_cb) {
		if(!mesh->store_cb(mesh, key, data, len)) {
			logger(mesh, MESHLINK_ERROR, "Cannot write config file: %s", strerror(errno));
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		} else {
			return true;
		}
	}

	char filename[PATH_MAX];
	snprintf(filename, sizeof(filename), "%s" SLASH "%s", mesh->confbase, key);

	if(!len) {
		if(unlink(filename) && errno != ENOENT) {
			logger(mesh, MESHLINK_ERROR, "Failed to remove `%s': %s", filename, strerror(errno));
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		} else {
			return true;
		}
	}

	char tmp_filename[PATH_MAX];
	snprintf(tmp_filename, sizeof(tmp_filename), "%s" SLASH "%s.tmp", mesh->confbase, key);

	FILE *f = fopen(tmp_filename, "w");

	if(!f) {
		logger(mesh, MESHLINK_ERROR, "Failed to open `%s': %s", tmp_filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(fwrite(data, len, 1, f) != 1) {
		logger(mesh, MESHLINK_ERROR, "Cannot write config file: %s", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		fclose(f);
		return false;
	}

	if(fflush(f)) {
		logger(mesh, MESHLINK_ERROR, "Failed to flush file: %s", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		fclose(f);
		return false;
	}

	if(fsync(fileno(f))) {
		logger(mesh, MESHLINK_ERROR, "Failed to sync file: %s\n", strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		fclose(f);
		return false;
	}

	if(fclose(f)) {
		logger(mesh, MESHLINK_ERROR, "Failed to close `%s': %s", filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	if(rename(tmp_filename, filename)) {
		logger(mesh, MESHLINK_ERROR, "Failed to rename `%s' to `%s': %s", tmp_filename, filename, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	return true;
}

/// Read a configuration file, decrypting it if necessary.
bool config_load(meshlink_handle_t *mesh, const char *name, config_t *config) {
	size_t buflen = 256;
	uint8_t *buf = xmalloc(buflen);
	size_t len = buflen;

	if(!load(mesh, name, buf, &len)) {
		return false;
	}

	buf = xrealloc(buf, len);

	if(len > buflen) {
		buflen = len;

		if(!load(mesh, name, (void **)&buf, &len) || len != buflen) {
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}
	}

	if(mesh->config_key) {
		if(len < 12 + 16) {
			logger(mesh, MESHLINK_ERROR, "Cannot decrypt config file\n");
			meshlink_errno = MESHLINK_ESTORAGE;
			config_free(config);
			return false;
		}

		size_t decrypted_len = len - 12 - 16;
		uint8_t *decrypted = xmalloc(decrypted_len);

		chacha_poly1305_ctx_t *ctx = chacha_poly1305_init();
		chacha_poly1305_set_key(ctx, mesh->config_key);

		if(chacha_poly1305_decrypt_iv96(ctx, buf, buf + 12, len - 12, decrypted, &decrypted_len)) {
			chacha_poly1305_exit(ctx);
			free(buf);
			buf = decrypted;
			len = decrypted_len;
		} else {
			logger(mesh, MESHLINK_ERROR, "Cannot decrypt config file\n");
			meshlink_errno = MESHLINK_ESTORAGE;
			chacha_poly1305_exit(ctx);
			free(decrypted);
			free(buf);
			return false;
		}
	}

	config->buf = buf;
	config->len = len;

	return true;
}

bool config_exists(meshlink_handle_t *mesh, const char *name) {
	size_t len = 0;

	return load(mesh, name, NULL, &len) && len;
}

/// Write a configuration file, encrypting it if necessary.
bool config_store(meshlink_handle_t *mesh, const char *name, const config_t *config) {
	if(mesh->config_key) {
		size_t encrypted_len = config->len + 16; // length of encrypted data
		uint8_t encrypted[12 + encrypted_len]; // store sequence number at the start

		randomize(encrypted, 12);
		chacha_poly1305_ctx_t *ctx = chacha_poly1305_init();
		chacha_poly1305_set_key(ctx, mesh->config_key);

		if(!chacha_poly1305_encrypt_iv96(ctx, encrypted, config->buf, config->len, encrypted + 12, &encrypted_len)) {
			logger(mesh, MESHLINK_ERROR, "Cannot encrypt config file\n");
			meshlink_errno = MESHLINK_ESTORAGE;
			chacha_poly1305_exit(ctx);
			return false;
		}

		chacha_poly1305_exit(ctx);

		return store(mesh, name, encrypted, 12 + encrypted_len);
	}

	return store(mesh, name, config->buf, config->len);
}

/// Free resources of a loaded configuration file.
void config_free(config_t *config) {
	assert(!config->len || config->buf);

	free((uint8_t *)config->buf);
	config->buf = NULL;
	config->len = 0;
}

bool config_ls(meshlink_handle_t *mesh, config_scan_action_t action) {
	logger(mesh, MESHLINK_DEBUG, "ls(%p)", (void *)(intptr_t)action);

	if(!mesh->confbase) {
		return true;
	}

	if(mesh->ls_cb) {
		return mesh->ls_cb(mesh, action);
	}

	DIR *dir;
	struct dirent *ent;

	dir = opendir(mesh->confbase);

	if(!dir) {
		logger(mesh, MESHLINK_ERROR, "Could not open %s: %s", mesh->confbase, strerror(errno));
		meshlink_errno = MESHLINK_ESTORAGE;
		return false;
	}

	while((ent = readdir(dir))) {
		if(ent->d_name[0] == '.') {
			continue;
		}

		if(!action(mesh, ent->d_name, 0)) {
			closedir(dir);
			return false;
		}
	}

	closedir(dir);
	return true;
}

/// Re-encrypt a configuration file.
static bool change_key(meshlink_handle_t *mesh, const char *name, size_t len) {
	(void)len;
	config_t config;

	if(!config_load(mesh, name, &config)) {
		return false;
	}

	size_t name_len = strlen(name);
	char new_name[name_len + 3];
	memcpy(new_name, name, name_len);

	if(name_len == 13 && name[8] == '.') {
		// Update meshlink.conf in-place
		new_name[name_len] = 0;
	} else {
		memcpy(new_name + name_len, ".r", 3);
	}

	void *orig_key = mesh->config_key;
	mesh->config_key = mesh->config_new_key;
	bool result = config_store(mesh, new_name, &config);
	mesh->config_key = orig_key;

	return result;
}

static bool change_node_key(meshlink_handle_t *mesh, const char *name, size_t len) {
	if(!check_id(name)) {
		return true;
	}

	return change_key(mesh, name, len);
}

static bool cleanup_old_file(meshlink_handle_t *mesh, const char *name, size_t len) {
	(void)len;
	size_t name_len = strlen(name);

	if(name_len < 3 || name[name_len - 2] != '.' || name[name_len - 1] != 'r') {
		return true;
	}

	config_t config;

	if(!config_load(mesh, name, &config)) {
		return false;
	}

	char new_name[name_len - 1];
	memcpy(new_name, name, name_len - 2);
	new_name[name_len - 2] = '\0';

	return config_store(mesh, new_name, &config) && store(mesh, name, NULL, 0);
}

bool config_cleanup_old_files(meshlink_handle_t *mesh) {
	return config_ls(mesh, cleanup_old_file);
}

bool config_change_key(meshlink_handle_t *mesh, void *new_key) {
	extern bool (*devtool_keyrotate_probe)(int stage);
	mesh->config_new_key = new_key;

	if(!config_ls(mesh, change_node_key)) {
		return false;
	}

	if(!devtool_keyrotate_probe(1)) {
		return false;
	}

	if(!change_key(mesh, "meshlink.conf", 0)) {
		return false;
	}

	free(mesh->config_key);
	mesh->config_key = new_key;

	if(!devtool_keyrotate_probe(2)) {
		return true;
	}

	config_cleanup_old_files(mesh);

	devtool_keyrotate_probe(3);

	return true;
}

/// Initialize the configuration directory
bool config_init(meshlink_handle_t *mesh, const struct meshlink_open_params *params) {
	if(!mesh->confbase) {
		return true;
	}

	if(!mesh->load_cb) {
		if(mkdir(mesh->confbase, 0700) && errno != EEXIST) {
			logger(NULL, MESHLINK_ERROR, "Cannot create configuration directory %s: %s", mesh->confbase, strerror(errno));
			meshlink_close(mesh);
			meshlink_errno = MESHLINK_ESTORAGE;
			return NULL;
		}

		mesh->lockfile = fopen(params->lock_filename, "w+");

		if(!mesh->lockfile) {
			logger(NULL, MESHLINK_ERROR, "Cannot not open %s: %s\n", params->lock_filename, strerror(errno));
			meshlink_errno = MESHLINK_ESTORAGE;
			return false;
		}

#ifdef FD_CLOEXEC
		fcntl(fileno(mesh->lockfile), F_SETFD, FD_CLOEXEC);
#endif

#ifdef HAVE_FLOCK

		if(flock(fileno(mesh->lockfile), LOCK_EX | LOCK_NB) != 0) {
			logger(NULL, MESHLINK_ERROR, "Cannot lock %s: %s\n", params->lock_filename, strerror(errno));
			fclose(mesh->lockfile);
			mesh->lockfile = NULL;
			meshlink_errno = MESHLINK_EBUSY;
			return false;
		}

#endif
	}

	return true;
}

void config_exit(meshlink_handle_t *mesh) {
	if(mesh->lockfile) {
		fclose(mesh->lockfile);
		mesh->lockfile = NULL;
	}
}