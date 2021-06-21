/*
    protocol_key.c -- handle the meta-protocol, key exchange
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

#include "connection.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "prf.h"
#include "protocol.h"
#include "sptps.h"
#include "utils.h"
#include "xalloc.h"

bool key_changed_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)c;
	(void)request;
	return true;
}

bool req_key_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)c;
	(void)request;
	return true;
}

bool ans_key_h(meshlink_handle_t *mesh, connection_t *c, const char *request) {
	(void)mesh;
	(void)c;
	(void)request;
	return true;
}