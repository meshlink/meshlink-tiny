#ifndef MESHLINK_INTERNAL_H
#define MESHLINK_INTERNAL_H

/*
    meshlink_internal.h -- Internal parts of the public API.
    Copyright (C) 2014-2019 Guus Sliepen <guus@meshlink.io>

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

#ifdef MESHLINK_H
#error You must not include both meshlink-tiny.h and meshlink_internal.h!
#endif

#include "system.h"

#include "event.h"
#include "hash.h"
#include "meshlink-tiny.h"
#include "meshlink_queue.h"
#include "sockaddr.h"
#include "sptps.h"
#include "xoshiro.h"

#include <pthread.h>

#define MAXSOCKETS 4    /* Probably overkill... */

static const char meshlink_invitation_label[] = "MeshLink invitation";
static const char meshlink_tcp_label[] = "MeshLink TCP";
static const char meshlink_udp_label[] = "MeshLink UDP";

#define MESHLINK_CONFIG_VERSION 2
#define MESHLINK_INVITATION_VERSION 2

#define CORE_MESH "."

struct meshlink_open_params {
	char *confbase;
	char *lock_filename;
	char *appname;
	char *name;
	dev_class_t devclass;

	int netns;

	const void *key;
	size_t keylen;
	meshlink_storage_policy_t storage_policy;
};

/// Device class traits
typedef struct {
	int pinginterval;
	int pingtimeout;
	int fast_retry_period;
	int maxtimeout;
	unsigned int min_connects;
	unsigned int max_connects;
	int edge_weight;
} dev_class_traits_t;

/// A handle for an instance of MeshLink.
struct meshlink_handle {
	// public members
	char *name;
	void *priv;

	// private members
	pthread_mutex_t mutex;
	event_loop_t loop;
	struct node_t *self;
	meshlink_log_cb_t log_cb;
	meshlink_log_level_t log_level;
	void *packet;

	// The most important network-related members come first
	int reachable;

	meshlink_receive_cb_t receive_cb;
	meshlink_queue_t outpacketqueue;
	signal_t datafromapp;

	struct node_t *peer;
	struct connection_t *connection;
	struct outgoing_t *outgoing;

	int contradicting_add_edge;
	int contradicting_del_edge;
	int sleeptime;
	time_t last_unreachable;
	timeout_t pingtimer;
	timeout_t periodictimer;

	struct connection_t *everyone;
	uint64_t prng_state[4];
	uint32_t session_id;

	// Infrequently used callbacks
	meshlink_node_status_cb_t node_status_cb;
	meshlink_node_status_cb_t meta_status_cb;
	meshlink_node_duplicate_cb_t node_duplicate_cb;
	meshlink_connection_try_cb_t connection_try_cb;
	meshlink_error_cb_t error_cb;

	// Mesh parameters
	char *appname;
	char *myport;

	struct ecdsa *private_key;

	dev_class_t devclass;

	dev_class_traits_t dev_class_traits[DEV_CLASS_COUNT];

	int netns;

	bool inviter_commits_first;

	// Configuration
	char *confbase;
	FILE *lockfile;
	void *config_key;
	char *external_address_url;
	meshlink_storage_policy_t storage_policy;

	// Thread management
	pthread_t thread;
	pthread_cond_t cond;
	bool threadstarted;
};

/// A handle for a MeshLink node.
struct meshlink_node {
	const char *name;
	void *priv;
};

void meshlink_send_from_queue(event_loop_t *loop, void *mesh);
void update_node_status(meshlink_handle_t *mesh, struct node_t *n);
extern meshlink_log_level_t global_log_level;
extern meshlink_log_cb_t global_log_cb;
void handle_duplicate_node(meshlink_handle_t *mesh, struct node_t *n);
void handle_network_change(meshlink_handle_t *mesh, bool online);
void call_error_cb(meshlink_handle_t *mesh, meshlink_errno_t meshlink_errno);

/// Per-instance PRNG
static inline int prng(meshlink_handle_t *mesh, uint64_t max) {
	return xoshiro(mesh->prng_state) % max;
}

/// Fudge value of ~0.1 seconds, in microseconds.
static const unsigned int TIMER_FUDGE = 0x8000000;

#endif
