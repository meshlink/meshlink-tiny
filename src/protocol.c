/*
    protocol.c -- handle the meta-protocol, basic functions
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
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

/* Jumptable for the request handlers */

static bool (*request_handlers[NUM_REQUESTS])(meshlink_handle_t *, connection_t *, const char *) = {
	[ID] = id_h,
	[ACK] = ack_h,
	[STATUS] = status_h,
	[ERROR] = error_h,
	[TERMREQ] = termreq_h,
	[PING] = ping_h,
	[PONG] = pong_h,
	[ADD_EDGE] = add_edge_h,
	[DEL_EDGE] = del_edge_h,
	[KEY_CHANGED] = key_changed_h,
	[REQ_KEY] = req_key_h,
	[ANS_KEY] = ans_key_h,
};

/* Request names */

static const char *request_name[NUM_REQUESTS] = {
	[ID] = "ID",
	[ACK] = "ACK",
	[STATUS] = "STATUS",
	[ERROR] = "ERROR",
	[TERMREQ] = "TERMREQ",
	[PING] = "PING",
	[PONG] = "PONG",
	[ADD_EDGE] = "ADD_EDGE",
	[DEL_EDGE] = "DEL_EDGE",
	[KEY_CHANGED] = "KEY_CHANGED",
	[REQ_KEY] = "REQ_KEY",
	[ANS_KEY] = "ANS_KEY",
};

bool check_id(const char *id) {
	if(!id || !*id) {
		return false;
	}

	for(; *id; id++)
		if(!isalnum(*id) && *id != '_' && *id != '-') {
			return false;
		}

	return true;
}

/* Generic request routines - takes care of logging and error
   detection as well */

bool send_request(meshlink_handle_t *mesh, connection_t *c, const char *format, ...) {
	assert(format);
	assert(*format);

	if(!c) {
		logger(mesh, MESHLINK_ERROR, "Trying to send request to non-existing connection");
		return false;
	}

	va_list args;
	char request[MAXBUFSIZE];
	int len;

	/* Use vsnprintf instead of vxasprintf: faster, no memory
	   fragmentation, cleanup is automatic, and there is a limit on the
	   input buffer anyway */

	va_start(args, format);
	len = vsnprintf(request, MAXBUFSIZE, format, args);
	va_end(args);

	if(len < 0 || len > MAXBUFSIZE - 1) {
		logger(mesh, MESHLINK_ERROR, "Output buffer overflow while sending request to %s", c->name);
		return false;
	}

	logger(mesh, MESHLINK_DEBUG, "Sending %s to %s: %s", request_name[atoi(request)], c->name, request);

	request[len++] = '\n';

	if(c == mesh->everyone) {
		broadcast_meta(mesh, NULL, request, len);
		return true;
	} else {
		return send_meta(mesh, c, request, len);
	}
}

bool receive_request(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	assert(request);

	int reqno = atoi(request);

	if(reqno || *request == '0') {
		if((reqno < 0) || (reqno >= NUM_REQUESTS) || !request_handlers[reqno]) {
			logger(mesh, MESHLINK_DEBUG, "Unknown request from %s: %s", c->name, request);
			return false;
		} else {
			logger(mesh, MESHLINK_DEBUG, "Got %s from %s: %s", request_name[reqno], c->name, request);
		}

		if((c->allow_request != ALL) && (c->allow_request != reqno) && (reqno != ERROR)) {
			logger(mesh, MESHLINK_ERROR, "Unauthorized request from %s", c->name);
			return false;
		}

		if(!request_handlers[reqno](mesh, c, request)) {
			/* Something went wrong. Probably scriptkiddies. Terminate. */

			logger(mesh, MESHLINK_ERROR, "Error while processing %s from %s", request_name[reqno], c->name);
			return false;
		}
	} else {
		logger(mesh, MESHLINK_ERROR, "Bogus data received from %s", c->name);
		return false;
	}

	return true;
}
