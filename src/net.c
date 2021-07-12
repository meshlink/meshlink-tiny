/*
    net.c -- most of the network code
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

#include "utils.h"
#include "conf.h"
#include "connection.h"
#include "devtools.h"
#include "logger.h"
#include "meshlink_internal.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "sptps.h"
#include "xalloc.h"

#include <assert.h>

#if !defined(min)
static inline int min(int a, int b) {
	return a < b ? a : b;
}
#endif

static const int default_timeout = 5;
static const int default_interval = 60;

/*
  Terminate a connection:
  - Mark it as inactive
  - Kill it with fire
  - Check if we need to retry making an outgoing connection
*/
void terminate_connection(meshlink_handle_t *mesh, connection_t *c, bool report) {
	(void)report;

	if(c->status.active) {
		logger(mesh, MESHLINK_INFO, "Closing connection with %s", c->name);
	}

	if(c->node && c->node->connection == c) {
		if(c->status.active && mesh->meta_status_cb) {
			mesh->meta_status_cb(mesh, (meshlink_node_t *)c->node, false);
		}

		c->node->connection = NULL;
		c->node->status.reachable = false;
		update_node_status(mesh, c->node);
	}

	c->status.active = false;

	outgoing_t *outgoing = c->outgoing;
	connection_del(mesh, c);

	/* Check if this was our outgoing connection */

	if(outgoing) {
		do_outgoing_connection(mesh, outgoing);
	}
}

/*
  Check if the other end is active.
  If we have sent packets, but didn't receive any,
  then possibly the other end is dead. We send a
  PING request over the meta connection. If the other
  end does not reply in time, we consider them dead
  and close the connection.
*/
static void timeout_handler(event_loop_t *loop, void *data) {
	assert(data);

	meshlink_handle_t *mesh = loop->data;
	logger(mesh, MESHLINK_DEBUG, "timeout_handler()");

	for(connection_t *c = mesh->connection; c; c = NULL) {
		int pingtimeout = c->node ? mesh->dev_class_traits[c->node->devclass].pingtimeout : default_timeout;
		int pinginterval = c->node ? mesh->dev_class_traits[c->node->devclass].pinginterval : default_interval;

		if(c->outgoing && !c->status.active && c->outgoing->timeout < 5) {
			pingtimeout = 1;
		}

		// Also make sure that if outstanding key requests for the UDP counterpart of a connection has timed out, we restart it.
		if(c->status.active && c->last_key_renewal + 3600 < mesh->loop.now.tv_sec) {
			devtool_sptps_renewal_probe((meshlink_node_t *)c->node);

			if(!sptps_force_kex(&c->sptps)) {
				logger(mesh, MESHLINK_ERROR, "SPTPS key renewal for connection with %s failed", c->name);
				terminate_connection(mesh, c, true);
				continue;
			} else {
				c->last_key_renewal = mesh->loop.now.tv_sec;
			}
		}

		if(c->last_ping_time + pingtimeout < mesh->loop.now.tv_sec) {
			if(c->status.active) {
				if(c->status.pinged) {
					logger(mesh, MESHLINK_INFO, "%s didn't respond to PING in %ld seconds", c->name, (long)mesh->loop.now.tv_sec - c->last_ping_time);
				} else if(c->last_ping_time + pinginterval <= mesh->loop.now.tv_sec) {
					send_ping(mesh, c);
					continue;
				} else {
					continue;
				}
			} else {
				if(c->status.connecting) {
					logger(mesh, MESHLINK_WARNING, "Timeout while connecting to %s", c->name);
				} else {
					logger(mesh, MESHLINK_WARNING, "Timeout from %s during authentication", c->name);
				}
			}

			terminate_connection(mesh, c, c->status.active);
		}
	}

	timeout_set(&mesh->loop, data, &(struct timespec) {
		1, prng(mesh, TIMER_FUDGE)
	});
}

static void periodic_handler(event_loop_t *loop, void *data) {
	meshlink_handle_t *mesh = loop->data;

	/* Check if there are too many contradicting ADD_EDGE and DEL_EDGE messages.
	   This usually only happens when another node has the same Name as this node.
	   If so, sleep for a short while to prevent a storm of contradicting messages.
	*/

	if(mesh->contradicting_del_edge > 100 && mesh->contradicting_add_edge > 100) {
		logger(mesh, MESHLINK_WARNING, "Possible node with same Name as us! Sleeping %d seconds.", mesh->sleeptime);
		struct timespec ts = {mesh->sleeptime, 0};
		usleep(ts.tv_sec * 1000000);
		mesh->sleeptime *= 2;

		if(mesh->sleeptime < 0) {
			mesh->sleeptime = 3600;
		}
	} else {
		mesh->sleeptime /= 2;

		if(mesh->sleeptime < 10) {
			mesh->sleeptime = 10;
		}
	}

	mesh->contradicting_add_edge = 0;
	mesh->contradicting_del_edge = 0;

	int timeout = default_timeout;

	/* Check if we need to make or break connections. */

	if(mesh->peer && !mesh->connection && !mesh->outgoing) {
		logger(mesh, MESHLINK_DEBUG, "Autoconnecting to %s", mesh->peer->name);
		mesh->outgoing = xzalloc(sizeof(outgoing_t));
		mesh->outgoing->node = mesh->peer;
		setup_outgoing_connection(mesh, mesh->outgoing);
	}

	for(node_t *n = mesh->peer; n; n = NULL) {
		if(n->status.dirty) {
			if(!node_write_config(mesh, n, false)) {
				logger(mesh, MESHLINK_DEBUG, "Could not update %s", n->name);
			}
		}
	}

	timeout_set(&mesh->loop, data, &(struct timespec) {
		timeout, prng(mesh, TIMER_FUDGE)
	});
}

void handle_meta_connection_data(meshlink_handle_t *mesh, connection_t *c) {
	if(!receive_meta(mesh, c)) {
		terminate_connection(mesh, c, c->status.active);
		return;
	}
}

void retry(meshlink_handle_t *mesh) {
	/* Reset the reconnection timers for all outgoing connections */
	for(outgoing_t *outgoing = mesh->outgoing; outgoing; outgoing = NULL) {
		outgoing->timeout = 0;

		if(outgoing->ev.cb) {
			timeout_set(&mesh->loop, &outgoing->ev, &(struct timespec) {
				0, 0
			});
		}
	}

	/* For active connections, check if their addresses are still valid.
	 * If yes, reset their ping timers, otherwise terminate them. */
	for(connection_t *c = mesh->connection; c; c = NULL) {
		if(!c->status.active) {
			continue;
		}

		if(!c->status.pinged) {
			c->last_ping_time = -3600;
		}

		sockaddr_t sa;
		socklen_t salen = sizeof(sa);

		if(getsockname(c->socket, &sa.sa, &salen)) {
			continue;
		}

		switch(sa.sa.sa_family) {
		case AF_INET:
			sa.in.sin_port = 0;
			break;

		case AF_INET6:
			sa.in6.sin6_port = 0;
			break;

		default:
			continue;
		}

		int sock = socket(sa.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

		if(sock == -1) {
			continue;
		}

		if(bind(sock, &sa.sa, salen) && errno == EADDRNOTAVAIL) {
			logger(mesh, MESHLINK_DEBUG, "Local address for connection to %s no longer valid, terminating", c->name);
			terminate_connection(mesh, c, c->status.active);
		}

		closesocket(sock);
	}

	/* Kick the ping timeout handler */
	if(mesh->pingtimer.cb) {
		timeout_set(&mesh->loop, &mesh->pingtimer, &(struct timespec) {
			0, 0
		});
	}
}

/*
  this is where it all happens...
*/
void main_loop(meshlink_handle_t *mesh) {
	timeout_add(&mesh->loop, &mesh->pingtimer, timeout_handler, &mesh->pingtimer, &(struct timespec) {
		1, prng(mesh, TIMER_FUDGE)
	});
	timeout_add(&mesh->loop, &mesh->periodictimer, periodic_handler, &mesh->periodictimer, &(struct timespec) {
		0, 0
	});

	//Add signal handler
	mesh->datafromapp.signum = 0;
	signal_add(&mesh->loop, &mesh->datafromapp, meshlink_send_from_queue, mesh, mesh->datafromapp.signum);

	if(!event_loop_run(&mesh->loop, mesh)) {
		logger(mesh, MESHLINK_ERROR, "Error while waiting for input: %s", strerror(errno));
		call_error_cb(mesh, MESHLINK_ENETWORK);
	}

	signal_del(&mesh->loop, &mesh->datafromapp);
	timeout_del(&mesh->loop, &mesh->periodictimer);
	timeout_del(&mesh->loop, &mesh->pingtimer);
}
