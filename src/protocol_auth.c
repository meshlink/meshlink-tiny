/*
    protocol_auth.c -- handle the meta-protocol, authentication
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
#include "devtools.h"
#include "ecdsa.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "packmsg.h"
#include "prf.h"
#include "protocol.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"
#include "ed25519/sha512.h"

#include <assert.h>

extern bool node_write_devclass(meshlink_handle_t *mesh, node_t *n);

bool send_id(meshlink_handle_t *mesh, connection_t *c) {
	return send_request(mesh, c, "%d %s %d.%d %s", ID, mesh->self->name, PROT_MAJOR, PROT_MINOR, mesh->appname);
}

bool id_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	char name[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %d.%d", name, &c->protocol_major, &c->protocol_minor) < 2) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s", "ID", c->name);
		return false;
	}

	/* Check if identity is a valid name */

	if(!check_id(name)) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "ID", c->name, "invalid name");
		return false;
	}

	/* If this is an outgoing connection, make sure we are connected to the right host */

	if(c->outgoing) {
		if(strcmp(c->name, name)) {
			logger(mesh, MESHLINK_ERROR, "Peer is %s instead of %s", name, c->name);
			return false;
		}
	} else {
		if(c->name) {
			free(c->name);
		}

		c->name = xstrdup(name);
	}

	/* Check if version matches */

	if(c->protocol_major != PROT_MAJOR) {
		logger(mesh, MESHLINK_ERROR, "Peer %s uses incompatible version %d.%d",
		       c->name, c->protocol_major, c->protocol_minor);
		return false;
	}

	/* Check if we know this node */

	node_t *n = lookup_node(mesh, c->name);

	if(!n) {
		logger(mesh, MESHLINK_ERROR, "Peer %s has unknown identity", c->name);
		return false;
	}

	if(!node_read_public_key(mesh, n)) {
		logger(mesh, MESHLINK_ERROR, "No key known for peer %s", c->name);

		if(n->status.reachable && !n->status.waitingforkey) {
			logger(mesh, MESHLINK_INFO, "Requesting key from peer %s", c->name);
			send_req_key(mesh, n);
		}

		return false;
	}

	/* Forbid version rollback for nodes whose ECDSA key we know */

	if(ecdsa_active(c->ecdsa) && c->protocol_minor < 2) {
		logger(mesh, MESHLINK_ERROR, "Peer %s tries to roll back protocol version to %d.%d",
		       c->name, c->protocol_major, c->protocol_minor);
		return false;
	}

	c->allow_request = ACK;
	c->last_ping_time = mesh->loop.now.tv_sec;
	char label[sizeof(meshlink_tcp_label) + strlen(mesh->self->name) + strlen(c->name) + 2];

	if(c->outgoing) {
		snprintf(label, sizeof(label), "%s %s %s", meshlink_tcp_label, mesh->self->name, c->name);
	} else {
		snprintf(label, sizeof(label), "%s %s %s", meshlink_tcp_label, c->name, mesh->self->name);
	}

	if(mesh->log_level <= MESHLINK_DEBUG) {
		char buf1[1024], buf2[1024];
		bin2hex((uint8_t *)mesh->private_key + 64, buf1, 32);
		bin2hex((uint8_t *)n->ecdsa + 64, buf2, 32);
		logger(mesh, MESHLINK_DEBUG, "Connection to %s mykey %s hiskey %s", c->name, buf1, buf2);
	}

	return sptps_start(&c->sptps, c, c->outgoing, false, mesh->private_key, n->ecdsa, label, sizeof(label) - 1, send_meta_sptps, receive_meta_sptps);
}

bool send_ack(meshlink_handle_t *mesh, connection_t *c) {
	node_t *n = lookup_node(mesh, c->name);

	if(n && n->status.blacklisted) {
		logger(mesh, MESHLINK_WARNING, "Peer %s is blacklisted", c->name);
		return send_error(mesh, c, BLACKLISTED, "blacklisted");
	}

	c->last_ping_time = mesh->loop.now.tv_sec;
	return send_request(mesh, c, "%d %s %d %x", ACK, mesh->myport, mesh->devclass, OPTION_PMTU_DISCOVERY | (PROT_MINOR << 24));
}

bool ack_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	char hisport[MAX_STRING_SIZE];
	int devclass;
	uint32_t options;
	node_t *n;

	if(sscanf(request, "%*d " MAX_STRING " %d %x", hisport, &devclass, &options) != 3) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s", "ACK", c->name);
		return false;
	}

	if(devclass < 0 || devclass >= DEV_CLASS_COUNT) {
		logger(mesh, MESHLINK_ERROR, "Got bad %s from %s: %s", "ACK", c->name, "devclass invalid");
		return false;
	}

	/* Check if we already have a node_t for him */

	n = lookup_node(mesh, c->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(c->name);
		node_add(mesh, n);
	}

	n->devclass = devclass;
	n->status.dirty = true;

	n->last_successfull_connection = mesh->loop.now.tv_sec;

	n->connection = c;
	n->nexthop = n;
	c->node = n;

	/* Activate this connection */

	c->allow_request = ALL;
	c->last_key_renewal = mesh->loop.now.tv_sec;
	c->status.active = true;

	logger(mesh, MESHLINK_INFO, "Connection with %s activated", c->name);

	if(mesh->meta_status_cb) {
		mesh->meta_status_cb(mesh, (meshlink_node_t *)n, true);
	}

	/* TODO: Create an edge_t for this connection, send it */

	/* Request a session key to jump start UDP traffic */

	if(c->status.initiator) {
		send_req_key(mesh, n);
	}

	return true;
}
