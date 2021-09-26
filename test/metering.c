#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "meshlink-tiny.h"
#include "devtools.h"
#include "netns_utils.h"
#include "utils.h"

#include "full.h"

static void print_counters(peer_config_t *peers, const char *description) {
	printf("%s:\n", description);
	printf("        %9s %9s %9s %9s %9s %9s\n",
	       "in data",
	       "forward",
	       "meta",
	       "out data",
	       "forward",
	       "meta");

	assert(peers[0].full);

	for(int i = 0; i < 3; i++) {
		meshlink_node_t *node = full_meshlink_get_node(peers[0].mesh, peers[i].name);
		assert(node);
		struct devtool_node_status status;
		full_devtool_reset_node_counters(peers[0].mesh, node, &status);
		printf(" %5s: %9" PRIu64 " %9" PRIu64 " %9" PRIu64 " %9" PRIu64 " %9" PRIu64 " %9" PRIu64 "\n",
		       node->name,
		       status.in_data,
		       status.in_forward,
		       status.in_meta,
		       status.out_data,
		       status.out_forward,
		       status.out_meta);
	}
}


int main(void) {
	init_full();

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	// Set up relay, peer and NUT
	peer_config_t *peers = setup_relay_peer_nut("metering");

	// Ensure DEV_CLASS_STATIONARY uses a 5 minute ping time
	for(int i = 0; i < 3; i++) {
		peers[i].full
		? full_meshlink_set_dev_class_timeouts(peers[i].mesh, DEV_CLASS_STATIONARY, 300, 5)
		: meshlink_set_dev_class_timeouts(peers[i].mesh, DEV_CLASS_BACKBONE, 300, 5);
	}

	for(int i = 0; i < 3; i++) {
		assert(peers[i].full
		       ? full_meshlink_start(peers[i].mesh)
		       : meshlink_start(peers[i].mesh)
		      );
	}

	// Measure traffic after 1 minute of PMTU probing
	sleep(60);
	print_counters(peers, "PMTU probing (1 min)");

	// Measure traffic after 1 minute of idle
	for(int i = 0; i < 10; i++) {
		sleep(60);
		print_counters(peers, "Idle (1 min)");
	}

	close_relay_peer_nut(peers);
}
