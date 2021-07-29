#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>

#include "full.h"
#include "meshlink-tiny.h"
#include "utils.h"

int main(void) {
	init_full();

	full_meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *mesh1;
	meshlink_handle_t *mesh2;

	// Open two instances

	assert(full_meshlink_destroy("storage-policy_conf.1"));
	assert(meshlink_destroy("storage-policy_conf.2"));

	mesh1 = full_meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_BACKBONE);
	assert(mesh1);
	assert(mesh2);
	full_meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_DISABLED);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_DISABLED);

	// Exchange data

	char *export1 = full_meshlink_export(mesh1);
	char *export2 = meshlink_export(mesh2);

	assert(export1);
	assert(export2);

	assert(full_meshlink_import(mesh1, export2));
	assert(meshlink_import(mesh2, export1));

	// Check that they know each other

	assert(full_meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	start_full_tiny_pair(mesh1, mesh2);

	// Close the instances and reopen them.

	close_full_tiny_pair(mesh1, mesh2);

	mesh1 = full_meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_BACKBONE);
	assert(mesh1);
	assert(mesh2);
	full_meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	// Check that the nodes no longer know each other

	assert(!full_meshlink_get_node(mesh1, "bar"));
	assert(!meshlink_get_node(mesh2, "foo"));

	// Exchange data again

	assert(full_meshlink_import(mesh1, export2));
	assert(meshlink_import(mesh2, export1));

	free(export1);
	free(export2);

	// Close the instances and reopen them.

	close_full_tiny_pair(mesh1, mesh2);

	mesh1 = full_meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_BACKBONE);
	assert(mesh1);
	assert(mesh2);
	full_meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	// Check that the nodes know each other

	assert(full_meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	// Check that if we change back to STORAGE_ENABLED right before closing, pending changes are still saved

	start_full_tiny_pair(mesh1, mesh2);
	stop_full_tiny_pair(mesh1, mesh2);

	full_meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_ENABLED);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_ENABLED);

	close_full_tiny_pair(mesh1, mesh2);

	mesh1 = full_meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_BACKBONE);
	assert(mesh1);
	assert(mesh2);

	// Close the instances and reopen them.

	close_full_tiny_pair(mesh1, mesh2);

	mesh1 = full_meshlink_open("storage-policy_conf.1", "foo", "storage-policy", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("storage-policy_conf.2", "bar", "storage-policy", DEV_CLASS_BACKBONE);
	assert(mesh1);
	assert(mesh2);
	full_meshlink_set_storage_policy(mesh1, MESHLINK_STORAGE_KEYS_ONLY);
	meshlink_set_storage_policy(mesh2, MESHLINK_STORAGE_KEYS_ONLY);

	// Check that the nodes know each other

	assert(full_meshlink_get_node(mesh1, "bar"));
	assert(meshlink_get_node(mesh2, "foo"));

	// Done.

	close_full_tiny_pair(mesh1, mesh2);
}
