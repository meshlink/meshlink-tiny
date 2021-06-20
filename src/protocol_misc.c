/*
    protocol_misc.c -- handle the meta-protocol, miscellaneous functions
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
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "utils.h"

int maxoutbufsize = 0;

/* Status and error notification routines */

bool status_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)c;
	(void)request;

	return true;
}

bool send_error(meshlink_handle_t *mesh, connection_t *c, request_error_t err, const char *message) {
	send_request(mesh, c, "%d %d %s", ERROR, err, message);
	flush_meta(mesh, c);
	return false;
}

bool error_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)c;
	(void)request;

	return false;
}

bool termreq_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)c;
	(void)request;

	return false;
}

bool send_ping(meshlink_handle_t *mesh, connection_t *c) {
	c->status.pinged = true;
	c->last_ping_time = mesh->loop.now.tv_sec;

	return send_request(mesh, c, "%d", PING);
}

bool ping_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)request;

	assert(request);
	assert(*request);

	return send_pong(mesh, c);
}

bool send_pong(meshlink_handle_t *mesh, connection_t *c) {
	return send_request(mesh, c, "%d", PONG);
}

bool pong_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)request;

	assert(request);
	assert(*request);

	c->status.pinged = false;

	/* Successful connection, reset timeout if this is an outgoing connection. */

	if(c->outgoing) {
		reset_outgoing(c->outgoing);
	}

	return true;
}
