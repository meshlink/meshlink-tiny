/*
    protocol_edge.c -- handle the meta-protocol, edges
    Copyright (C) 2014 Guus Sliepen <guus@meshlink.io>

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
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool send_add_edge(meshlink_handle_t *mesh, connection_t *c, int contradictions) {
	char *address, *port;
	sockaddr2str(&c->address, &address, &port);

	bool result = send_request(mesh, c, "%d %x %s %d %s %s %s %s %d %s %x %d %d %x", ADD_EDGE, prng(mesh, UINT_MAX),
	                           mesh->self->name, mesh->self->devclass, CORE_MESH,
	                           mesh->peer->name, address, port,
	                           mesh->peer->devclass, CORE_MESH, 0, 1000, contradictions, mesh->peer->session_id);

	free(address);
	free(port);

	return result;
}

bool add_edge_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	(void)mesh;
	(void)c;
	(void)request;

	return true;
}

bool del_edge_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);
	assert(*request);

	(void)mesh;
	(void)c;
	(void)request;

	return true;
}
