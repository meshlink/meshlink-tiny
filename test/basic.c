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
#include "utils.h"

int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	// Check that the first time we need to supply a name

	assert(meshlink_destroy("basic_conf"));

	meshlink_handle_t *mesh = meshlink_open("basic_conf", NULL, "basic", DEV_CLASS_BACKBONE);
	assert(!mesh);

	// Open a new meshlink instance.

	mesh = meshlink_open("basic_conf", "foo", "basic", DEV_CLASS_BACKBONE);
	assert(mesh);

	// Check that we can't open a second instance of the same node.

	meshlink_handle_t *mesh2 = meshlink_open("basic_conf", "foo", "basic", DEV_CLASS_BACKBONE);
	assert(!mesh2);

	// Check that we cannot destroy an instance that is in use.

	assert(!meshlink_destroy("basic_conf"));

	// Check that our own node exists.

	meshlink_node_t *self = meshlink_get_self(mesh);
	assert(self);
	assert(!strcmp(self->name, "foo"));

	// Start and stop the mesh.

	assert(meshlink_start(mesh));

	meshlink_stop(mesh);

	// Make sure we can start and stop the mesh again.

	assert(meshlink_start(mesh));
	assert(meshlink_start(mesh));
	meshlink_stop(mesh);
	meshlink_stop(mesh);

	// Close the mesh and open it again, now with a different name parameter.

	meshlink_close(mesh);
	mesh = meshlink_open("basic_conf", "bar", "basic", DEV_CLASS_BACKBONE);
	assert(!mesh);

	// Open it without providing a name

	mesh = meshlink_open("basic_conf", NULL, "basic", DEV_CLASS_BACKBONE);
	assert(mesh);

	self = meshlink_get_self(mesh);
	assert(self);
	assert(!strcmp(mesh->name, "foo"));
	assert(!strcmp(self->name, "foo"));

	// Check that the name is ignored now, and that we still are "foo".

	assert(!meshlink_get_node(mesh, "bar"));
	self = meshlink_get_self(mesh);
	assert(self);
	assert(!strcmp(self->name, "foo"));

	// Start and stop the mesh.

	assert(meshlink_start(mesh));
	meshlink_stop(mesh);
	meshlink_close(mesh);

	// Check that messing with the config directory will create a new instance.

	assert(unlink("basic_conf/meshlink.conf") == 0);
	mesh = meshlink_open("basic_conf", "bar", "basic", DEV_CLASS_BACKBONE);
	assert(mesh);
	assert(!meshlink_get_node(mesh, "foo"));
	self = meshlink_get_self(mesh);
	assert(self);
	assert(!strcmp(self->name, "bar"));
	assert(access("basic_conf/foo", X_OK) == -1 && errno == ENOENT);
	meshlink_close(mesh);

	// Destroy the mesh.

	assert(meshlink_destroy("basic_conf"));

	// Check that the configuration directory is completely empty.

	DIR *dir = opendir("basic_conf");

	if(dir) {
		struct dirent *ent;

		while((ent = readdir(dir))) {
			assert(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."));
		}

		closedir(dir);
	} else {
		assert(errno == ENOENT);
	}

	// Check that we can destroy it again.

	assert(meshlink_destroy("basic_conf"));
}
