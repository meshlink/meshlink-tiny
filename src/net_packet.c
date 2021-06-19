/*
    net_packet.c -- Handles in- and outgoing VPN packets
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
#include "crypto.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

int keylifetime = 0;

/* VPN packet I/O */

static void receive_packet(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet) {
	logger(mesh, MESHLINK_DEBUG, "Received packet of %d bytes from %s", packet->len, n->name);

	if(n->status.blacklisted) {
		logger(mesh, MESHLINK_WARNING, "Dropping packet from blacklisted node %s", n->name);
	} else {
		route(mesh, n, packet);
	}
}

static void send_sptps_packet(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.reachable) {
		logger(mesh, MESHLINK_ERROR, "Trying to send SPTPS data to unreachable node %s", n->name);
		return;
	}

	if(!n->status.validkey) {
		logger(mesh, MESHLINK_INFO, "No valid key known yet for %s", n->name);

		if(!n->status.waitingforkey) {
			send_req_key(mesh, n);
		} else if(n->last_req_key + 10 < mesh->loop.now.tv_sec) {
			logger(mesh, MESHLINK_DEBUG, "No key from %s after 10 seconds, restarting SPTPS", n->name);
			sptps_stop(&n->sptps);
			n->status.waitingforkey = false;
			send_req_key(mesh, n);
		}

		return;
	}

	uint8_t type = 0;

	// If it's a probe, send it immediately without trying to compress it.
	if(origpkt->probe) {
		sptps_send_record(&n->sptps, PKT_PROBE, origpkt->data, origpkt->len);
		return;
	}

	sptps_send_record(&n->sptps, type, origpkt->data, origpkt->len);
	return;
}

bool send_sptps_data(void *handle, uint8_t type, const void *data, size_t len) {
	assert(handle);
	assert(data);
	assert(len);

	node_t *to = handle;
	meshlink_handle_t *mesh = to->mesh;

	if(!to->status.reachable) {
		logger(mesh, MESHLINK_ERROR, "Trying to send SPTPS data to unreachable node %s", to->name);
		return false;
	}


	if(type == PKT_PROBE) {
		/* Probe packets are not supported. */
		return false;
	}

	/* Send it via TCP. */

	char buf[len * 4 / 3 + 5];
	b64encode(data, buf, len);

	if(!to->nexthop || !to->nexthop->connection) {
		logger(mesh, MESHLINK_WARNING, "Unable to forward SPTPS packet to %s via %s", to->name, to->nexthop ? to->nexthop->name : to->name);
		return false;
	}

	/* If no valid key is known yet, send the packets using ANS_KEY requests,
	   to ensure we get to learn the reflexive UDP address. */
	if(!to->status.validkey) {
		return send_request(mesh, to->nexthop->connection, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, mesh->self->name, to->name, buf, 0);
	} else {
		return send_request(mesh, to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, mesh->self->name, to->name, REQ_SPTPS, buf);
	}
}

bool receive_sptps_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	assert(handle);
	assert(!data || len);

	node_t *from = handle;
	meshlink_handle_t *mesh = from->mesh;

	if(type == SPTPS_HANDSHAKE) {
		if(!from->status.validkey) {
			logger(mesh, MESHLINK_INFO, "SPTPS key exchange with %s successful", from->name);
			from->status.validkey = true;
			from->status.waitingforkey = false;

			if(from->utcp) {
				utcp_reset_timers(from->utcp);
			}
		}

		return true;
	}

	if(len > MAXSIZE) {
		logger(mesh, MESHLINK_ERROR, "Packet from %s larger than maximum supported size (%d > %d)", from->name, len, MAXSIZE);
		return false;
	}

	vpn_packet_t inpkt;

	if(type == PKT_PROBE) {
		/* We shouldn't receive any UDP probe packets. */
		return false;
	} else {
		inpkt.probe = false;
	}

	if(type & ~(PKT_COMPRESSED)) {
		logger(mesh, MESHLINK_ERROR, "Unexpected SPTPS record type %d len %d from %s", type, len, from->name);
		return false;
	}

	if(type & PKT_COMPRESSED) {
		logger(mesh, MESHLINK_ERROR, "Error while decompressing packet from %s", from->name);
		return false;
	}

	memcpy(inpkt.data, data, len); // TODO: get rid of memcpy
	inpkt.len = len;

	receive_packet(mesh, from, &inpkt);
	return true;
}

/*
  send a packet to the given vpn ip.
*/
void send_packet(meshlink_handle_t *mesh, node_t *n, vpn_packet_t *packet) {
	if(n == mesh->self) {
		// TODO: send to application
		return;
	}

	logger(mesh, MESHLINK_DEBUG, "Sending packet of %d bytes to %s", packet->len, n->name);

	if(!n->status.reachable) {
		logger(mesh, MESHLINK_WARNING, "Node %s is not reachable", n->name);
		return;
	}

	send_sptps_packet(mesh, n, packet);
	return;
}
