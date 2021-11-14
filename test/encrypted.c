#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <dirent.h>

#include "meshlink-tiny.h"
#include "devtools.h"
#include "utils.h"

static int keyrotate_fail_stage;

static bool keyrotate_probe(int stage) {
	fprintf(stderr, "%d\n", stage);
	return stage != keyrotate_fail_stage;
}

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	devtool_keyrotate_probe = keyrotate_probe;

	// Open a new meshlink instance.

	assert(meshlink_destroy("encrypted_conf"));
	meshlink_handle_t *mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "right", 5);
	assert(mesh);

	// Close the mesh and open it again, now with a different key.

	meshlink_close(mesh);

	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "wrong", 5);
	assert(!mesh);

	// Open it again, now with the right key.

	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "right", 5);
	assert(mesh);

	// Rotate the key

	assert(meshlink_encrypted_key_rotate(mesh, "newkey", 6));

	// Check that we cannot open it with the old key

	meshlink_close(mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "right", 5);
	assert(!mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey", 6);
	assert(mesh);

	// Check how key rotation failures are handled

	keyrotate_fail_stage = 1; // Fail before committing to the new key
	assert(!meshlink_encrypted_key_rotate(mesh, "newkey2", 7));
	meshlink_close(mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey2", 7);
	assert(!mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey", 6);
	assert(mesh);

	keyrotate_fail_stage = 2; // Fail after committing to the new key, before cleaning up old files
	assert(meshlink_encrypted_key_rotate(mesh, "newkey3", 7));
	meshlink_close(mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey", 6);
	assert(!mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey3", 7);
	assert(mesh);

	keyrotate_fail_stage = 3; // Fail after committing to the new key and cleaning up old files
	assert(meshlink_encrypted_key_rotate(mesh, "newkey4", 7));
	meshlink_close(mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey3", 7);
	assert(!mesh);
	mesh = meshlink_open_encrypted("encrypted_conf", "foo", "encrypted", DEV_CLASS_BACKBONE, "newkey4", 7);
	assert(mesh);

	// That's it.

	meshlink_close(mesh);

	// Destroy the mesh.

	assert(meshlink_destroy("encrypted_conf"));

	DIR *dir = opendir("encrypted_conf");

	if(dir) {
		struct dirent *ent;

		while((ent = readdir(dir))) {
			fprintf(stderr, "%s\n", ent->d_name);
			assert(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."));
		}

		closedir(dir);
	} else {
		assert(errno == ENOENT);
	}

}
