/*
    node.c -- node tree management
    Copyright (C) 2014 Guus Sliepen <guus@meshlink.io>,

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

#include "hash.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "utils.h"
#include "xalloc.h"

void init_nodes(meshlink_handle_t *mesh) {
	mesh->peer = NULL;
}

void exit_nodes(meshlink_handle_t *mesh) {
	if(mesh->peer) {
		free_node(mesh->peer);
	}

	mesh->peer = NULL;
}

node_t *new_node(void) {
	node_t *n = xzalloc(sizeof(*n));

	n->mtu = MTU;
	n->maxmtu = MTU;
	n->devclass = DEV_CLASS_UNKNOWN;

	return n;
}

void free_node(node_t *n) {
	n->status.destroyed = true;

	utcp_exit(n->utcp);

	sockaddrfree(&n->address);

	ecdsa_free(n->ecdsa);
	sptps_stop(&n->sptps);

	if(n->mtutimeout.cb) {
		abort();
	}

	free(n->name);
	free(n->canonical_address);

	free(n);
}

void node_add(meshlink_handle_t *mesh, node_t *n) {
	if(n == mesh->self) {
		return;
	}

	assert(!mesh->peer);
	n->mesh = mesh;
	mesh->peer = n;
}

void node_del(meshlink_handle_t *mesh, node_t *n) {
	if(n == mesh->self) {
		return;
	}

	assert(mesh->peer && mesh->peer == n);
	timeout_del(&mesh->loop, &n->mtutimeout);
	free_node(n);
	mesh->peer = NULL;
}

node_t *lookup_node(meshlink_handle_t *mesh, const char *name) {
	if(mesh->peer && !strcmp(name, mesh->peer->name)) {
		return mesh->peer;
	} else if(!strcmp(name, mesh->self->name)) {
		return mesh->self;
	} else {
		return NULL;
	}
}

bool node_add_recent_address(meshlink_handle_t *mesh, node_t *n, const sockaddr_t *sa) {
	(void)mesh;
	bool found = false;
	int i;

	/* Check if we already know this address */
	for(i = 0; i < MAX_RECENT && n->recent[i].sa.sa_family; i++) {
		if(!sockaddrcmp(&n->recent[i], sa)) {
			found = true;
			break;
		}
	}

	if(found && i == 0) {
		/* It's already the most recent address, nothing to do. */
		return false;
	}

	if(i >= MAX_RECENT) {
		i = MAX_RECENT - 1;
	}

	memmove(n->recent + 1, n->recent, i * sizeof(*n->recent));
	memcpy(n->recent, sa, SALEN(sa->sa));

	n->status.dirty = true;
	return !found;
}
