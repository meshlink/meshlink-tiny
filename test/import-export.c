#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include "meshlink-tiny.h"
#include "utils.h"

static struct sync_flag bar_reachable;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "bar")) {
		set_sync_flag(&bar_reachable, true);
	}
}

int main(void) {
	init_sync_flag(&bar_reachable);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	// Open two new meshlink instance.

	assert(meshlink_destroy("import_export_conf.1"));
	assert(meshlink_destroy("import_export_conf.2"));

	meshlink_handle_t *mesh1 = meshlink_open("import_export_conf.1", "foo", "import-export", DEV_CLASS_BACKBONE);
	assert(mesh1);

	meshlink_handle_t *mesh2 = meshlink_open("import_export_conf.2", "bar", "import-export", DEV_CLASS_BACKBONE);
	assert(mesh2);

	// Import and export both side's data

	assert(meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));
	assert(meshlink_set_canonical_address(mesh2, meshlink_get_self(mesh2), "localhost", NULL));

	char *data = meshlink_export(mesh1);
	assert(data);

	assert(meshlink_import(mesh2, data));
	free(data);

	data = meshlink_export(mesh2);
	assert(data);

	assert(meshlink_import(mesh1, data));

	// Check that importing twice is fine
	assert(meshlink_import(mesh1, data));
	free(data);

	// Check that importing garbage is not fine
	assert(!meshlink_import(mesh1, "Garbage\n"));

	// Check that foo knows bar, but that it is not reachable.

	meshlink_node_t *bar = meshlink_get_node(mesh1, "bar");
	assert(bar);

	// Clean up.

	meshlink_close(mesh2);
	meshlink_close(mesh1);
}
