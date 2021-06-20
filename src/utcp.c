/*
    utcp.c -- Userspace TCP
    Copyright (C) 2014-2017 Guus Sliepen <guus@tinc-vpn.org>

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
#include <time.h>

#include "utcp_priv.h"

#ifndef EBADMSG
#define EBADMSG         104
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#ifdef poll
#undef poll
#endif

#ifndef UTCP_CLOCK
#if defined(CLOCK_MONOTONIC_RAW) && defined(__x86_64__)
#define UTCP_CLOCK CLOCK_MONOTONIC_RAW
#else
#define UTCP_CLOCK CLOCK_MONOTONIC
#endif
#endif

static void timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *r) {
	r->tv_sec = a->tv_sec - b->tv_sec;
	r->tv_nsec = a->tv_nsec - b->tv_nsec;

	if(r->tv_nsec < 0) {
		r->tv_sec--, r->tv_nsec += NSEC_PER_SEC;
	}
}

static int32_t timespec_diff_usec(const struct timespec *a, const struct timespec *b) {
	return (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_nsec - b->tv_nsec) / 1000;
}

static bool timespec_lt(const struct timespec *a, const struct timespec *b) {
	if(a->tv_sec == b->tv_sec) {
		return a->tv_nsec < b->tv_nsec;
	} else {
		return a->tv_sec < b->tv_sec;
	}
}

static void timespec_clear(struct timespec *a) {
	a->tv_sec = 0;
	a->tv_nsec = 0;
}

static bool timespec_isset(const struct timespec *a) {
	return a->tv_sec;
}

static long CLOCK_GRANULARITY; // usec

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

static inline size_t max(size_t a, size_t b) {
	return a > b ? a : b;
}

#ifdef UTCP_DEBUG
#include <stdarg.h>

#ifndef UTCP_DEBUG_DATALEN
#define UTCP_DEBUG_DATALEN 20
#endif

static void debug(struct utcp_connection *c, const char *format, ...) {
	struct timespec tv;
	char buf[1024];
	int len;

	clock_gettime(CLOCK_REALTIME, &tv);
	len = snprintf(buf, sizeof(buf), "%ld.%06lu %u:%u ", (long)tv.tv_sec, tv.tv_nsec / 1000, c ? c->src : 0, c ? c->dst : 0);
	va_list ap;
	va_start(ap, format);
	len += vsnprintf(buf + len, sizeof(buf) - len, format, ap);
	va_end(ap);

	if(len > 0 && (size_t)len < sizeof(buf)) {
		fwrite(buf, len, 1, stderr);
	}
}

static void print_packet(struct utcp_connection *c, const char *dir, const void *pkt, size_t len) {
	struct hdr hdr;

	if(len < sizeof(hdr)) {
		debug(c, "%s: short packet (%lu bytes)\n", dir, (unsigned long)len);
		return;
	}

	memcpy(&hdr, pkt, sizeof(hdr));

	uint32_t datalen;

	if(len > sizeof(hdr)) {
		datalen = min(len - sizeof(hdr), UTCP_DEBUG_DATALEN);
	} else {
		datalen = 0;
	}


	const uint8_t *data = (uint8_t *)pkt + sizeof(hdr);
	char str[datalen * 2 + 1];
	char *p = str;

	for(uint32_t i = 0; i < datalen; i++) {
		*p++ = "0123456789ABCDEF"[data[i] >> 4];
		*p++ = "0123456789ABCDEF"[data[i] & 15];
	}

	*p = 0;

	debug(c, "%s: len %lu src %u dst %u seq %u ack %u wnd %u aux %x ctl %s%s%s%s%s data %s\n",
	      dir, (unsigned long)len, hdr.src, hdr.dst, hdr.seq, hdr.ack, hdr.wnd, hdr.aux,
	      hdr.ctl & SYN ? "SYN" : "",
	      hdr.ctl & RST ? "RST" : "",
	      hdr.ctl & FIN ? "FIN" : "",
	      hdr.ctl & ACK ? "ACK" : "",
	      hdr.ctl & MF ? "MF" : "",
	      str
	     );
}

static void debug_cwnd(struct utcp_connection *c) {
	debug(c, "snd.cwnd %u snd.ssthresh %u\n", c->snd.cwnd, ~c->snd.ssthresh ? c->snd.ssthresh : 0);
}
#else
#define debug(...) do {} while(0)
#define print_packet(...) do {} while(0)
#define debug_cwnd(...) do {} while(0)
#endif

static void set_state(struct utcp_connection *c, enum state state) {
	c->state = state;

	if(state == ESTABLISHED) {
		timespec_clear(&c->conn_timeout);
	}

	debug(c, "state %s\n", strstate[state]);
}

static bool fin_wanted(struct utcp_connection *c, uint32_t seq) {
	if(seq != c->snd.last) {
		return false;
	}

	switch(c->state) {
	case FIN_WAIT_1:
	case CLOSING:
	case LAST_ACK:
		return true;

	default:
		return false;
	}
}

static int32_t seqdiff(uint32_t a, uint32_t b) {
	return a - b;
}

// Connections are stored in a sorted list.
// This gives O(log(N)) lookup time, O(N log(N)) insertion time and O(N) deletion time.

static int compare(const void *va, const void *vb) {
	assert(va && vb);

	const struct utcp_connection *a = *(struct utcp_connection **)va;
	const struct utcp_connection *b = *(struct utcp_connection **)vb;

	assert(a && b);

	int c = (int)a->src - (int)b->src;

	if(c) {
		return c;
	}

	c = (int)a->dst - (int)b->dst;
	return c;
}

static struct utcp_connection *find_connection(const struct utcp *utcp, uint16_t src, uint16_t dst) {
	if(!utcp->nconnections) {
		return NULL;
	}

	struct utcp_connection key = {
		.src = src,
		.dst = dst,
	}, *keyp = &key;
	struct utcp_connection **match = bsearch(&keyp, utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);
	return match ? *match : NULL;
}

static void free_connection(struct utcp_connection *c) {
	struct utcp *utcp = c->utcp;
	struct utcp_connection **cp = bsearch(&c, utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);

	assert(cp);

	int i = cp - utcp->connections;
	memmove(cp, cp + 1, (utcp->nconnections - i - 1) * sizeof(*cp));
	utcp->nconnections--;

	free(c);
}

static struct utcp_connection *allocate_connection(struct utcp *utcp, uint16_t src, uint16_t dst) {
	// Check whether this combination of src and dst is free

	if(src) {
		if(find_connection(utcp, src, dst)) {
			errno = EADDRINUSE;
			return NULL;
		}
	} else { // If src == 0, generate a random port number with the high bit set
		if(utcp->nconnections >= 32767) {
			errno = ENOMEM;
			return NULL;
		}

		src = rand() | 0x8000;

		while(find_connection(utcp, src, dst)) {
			src++;
		}
	}

	// Allocate memory for the new connection

	if(utcp->nconnections >= utcp->nallocated) {
		if(!utcp->nallocated) {
			utcp->nallocated = 4;
		} else {
			utcp->nallocated *= 2;
		}

		struct utcp_connection **new_array = realloc(utcp->connections, utcp->nallocated * sizeof(*utcp->connections));

		if(!new_array) {
			return NULL;
		}

		utcp->connections = new_array;
	}

	struct utcp_connection *c = calloc(1, sizeof(*c));

	if(!c) {
		return NULL;
	}

	// Fill in the details

	c->src = src;
	c->dst = dst;
#ifdef UTCP_DEBUG
	c->snd.iss = 0;
#else
	c->snd.iss = rand();
#endif
	c->snd.una = c->snd.iss;
	c->snd.nxt = c->snd.iss + 1;
	c->snd.last = c->snd.nxt;
	c->snd.cwnd = (utcp->mss > 2190 ? 2 : utcp->mss > 1095 ? 3 : 4) * utcp->mss;
	c->snd.ssthresh = ~0;
	debug_cwnd(c);
	c->srtt = 0;
	c->rttvar = 0;
	c->rto = START_RTO;
	c->utcp = utcp;

	// Add it to the sorted list of connections

	utcp->connections[utcp->nconnections++] = c;
	qsort(utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);

	return c;
}

static inline uint32_t absdiff(uint32_t a, uint32_t b) {
	if(a > b) {
		return a - b;
	} else {
		return b - a;
	}
}

// Update RTT variables. See RFC 6298.
static void update_rtt(struct utcp_connection *c, uint32_t rtt) {
	if(!rtt) {
		debug(c, "invalid rtt\n");
		return;
	}

	if(!c->srtt) {
		c->srtt = rtt;
		c->rttvar = rtt / 2;
	} else {
		c->rttvar = (c->rttvar * 3 + absdiff(c->srtt, rtt)) / 4;
		c->srtt = (c->srtt * 7 + rtt) / 8;
	}

	c->rto = c->srtt + max(4 * c->rttvar, CLOCK_GRANULARITY);

	if(c->rto > MAX_RTO) {
		c->rto = MAX_RTO;
	}

	debug(c, "rtt %u srtt %u rttvar %u rto %u\n", rtt, c->srtt, c->rttvar, c->rto);
}

static void start_retransmit_timer(struct utcp_connection *c) {
	clock_gettime(UTCP_CLOCK, &c->rtrx_timeout);

	uint32_t rto = c->rto;

	while(rto > USEC_PER_SEC) {
		c->rtrx_timeout.tv_sec++;
		rto -= USEC_PER_SEC;
	}

	c->rtrx_timeout.tv_nsec += rto * 1000;

	if(c->rtrx_timeout.tv_nsec >= NSEC_PER_SEC) {
		c->rtrx_timeout.tv_nsec -= NSEC_PER_SEC;
		c->rtrx_timeout.tv_sec++;
	}

	debug(c, "rtrx_timeout %ld.%06lu\n", c->rtrx_timeout.tv_sec, c->rtrx_timeout.tv_nsec);
}

static void stop_retransmit_timer(struct utcp_connection *c) {
	timespec_clear(&c->rtrx_timeout);
	debug(c, "rtrx_timeout cleared\n");
}

struct utcp_connection *utcp_connect_ex(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv, uint32_t flags) {
	struct utcp_connection *c = allocate_connection(utcp, 0, dst);

	if(!c) {
		return NULL;
	}

	assert(flags == 0); // UDP only

	c->flags = flags;
	c->recv = recv;
	c->priv = priv;

	struct {
		struct hdr hdr;
		uint8_t init[4];
	} pkt;

	pkt.hdr.src = c->src;
	pkt.hdr.dst = c->dst;
	pkt.hdr.seq = c->snd.iss;
	pkt.hdr.ack = 0;
	pkt.hdr.wnd = c->utcp->mtu;
	pkt.hdr.ctl = SYN;
	pkt.hdr.aux = 0x0101;
	pkt.init[0] = 1;
	pkt.init[1] = 0;
	pkt.init[2] = 0;
	pkt.init[3] = flags & 0x7;

	set_state(c, SYN_SENT);

	print_packet(c, "send", &pkt, sizeof(pkt));
	utcp->send(utcp, &pkt, sizeof(pkt));

	clock_gettime(UTCP_CLOCK, &c->conn_timeout);
	c->conn_timeout.tv_sec += utcp->timeout;

	start_retransmit_timer(c);

	return c;
}

void utcp_accept(struct utcp_connection *c, utcp_recv_t recv, void *priv) {
	if(c->reapable || c->state != SYN_RECEIVED) {
		debug(c, "accept() called on invalid connection in state %s\n", c, strstate[c->state]);
		return;
	}

	debug(c, "accepted %p %p\n", c, recv, priv);
	c->recv = recv;
	c->priv = priv;
	set_state(c, ESTABLISHED);
}

static void ack(struct utcp_connection *c, const void *data, size_t len) {
	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt = c->utcp->pkt;

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.ack = c->rcv.nxt;
	pkt->hdr.wnd = 0;
	pkt->hdr.ctl = ACK;
	pkt->hdr.aux = 0;

	uint32_t seglen = len;
	pkt->hdr.seq = c->snd.nxt;

	c->snd.nxt += seglen;

	if(fin_wanted(c, c->snd.nxt)) {
		pkt->hdr.ctl |= FIN;
	}

	if(data && len) {
		assert(len <= c->utcp->mtu);
		memcpy(pkt->data, data, len);
	} else {
		assert(!data && !len);
	}

	if(!c->rtt_start.tv_sec) {
		// Start RTT measurement
		clock_gettime(UTCP_CLOCK, &c->rtt_start);
		c->rtt_seq = pkt->hdr.seq + seglen;
		debug(c, "starting RTT measurement, expecting ack %u\n", c->rtt_seq);
	}

	print_packet(c, "send", pkt, sizeof(pkt->hdr) + seglen);
	c->utcp->send(c->utcp, pkt, sizeof(pkt->hdr) + seglen);
}

ssize_t utcp_send(struct utcp_connection *c, const void *data, size_t len) {
	if(c->reapable) {
		debug(c, "send() called on closed connection\n");
		errno = EBADF;
		return -1;
	}

	switch(c->state) {
	case CLOSED:
	case LISTEN:
		debug(c, "send() called on unconnected connection\n");
		errno = ENOTCONN;
		return -1;

	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case CLOSE_WAIT:
		break;

	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		debug(c, "send() called on closed connection\n");
		errno = EPIPE;
		return -1;
	}

	// Exit early if we have nothing to send.

	if(!len) {
		return 0;
	}

	if(!data) {
		errno = EFAULT;
		return -1;
	}

	if(len > MAX_UNRELIABLE_SIZE || len > c->utcp->mtu) {
		errno = EMSGSIZE;
		return -1;
	}

	if(len <= 0) {
		return len;
	}

	c->snd.last += len;

	// Don't send anything yet if the connection has not fully established yet

	if(c->state == SYN_SENT || c->state == SYN_RECEIVED) {
		return len;
	}

	ack(c, data, len);

	c->snd.una = c->snd.nxt = c->snd.last;

	return len;
}

static void swap_ports(struct hdr *hdr) {
	uint16_t tmp = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp;
}

static void retransmit(struct utcp_connection *c) {
	if(c->state == CLOSED || c->snd.last == c->snd.una) {
		debug(c, "retransmit() called but nothing to retransmit!\n");
		stop_retransmit_timer(c);
		return;
	}

	struct utcp *utcp = c->utcp;

	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt = c->utcp->pkt;

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.wnd = c->utcp->mtu;
	pkt->hdr.aux = 0;

	switch(c->state) {
	case SYN_SENT:
		// Send our SYN again
		pkt->hdr.seq = c->snd.iss;
		pkt->hdr.ack = 0;
		pkt->hdr.ctl = SYN;
		pkt->hdr.aux = 0x0101;
		pkt->data[0] = 1;
		pkt->data[1] = 0;
		pkt->data[2] = 0;
		pkt->data[3] = c->flags & 0x7;
		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr) + 4);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + 4);
		break;

	case SYN_RECEIVED:
		// Send SYNACK again
		pkt->hdr.seq = c->snd.nxt;
		pkt->hdr.ack = c->rcv.nxt;
		pkt->hdr.ctl = SYN | ACK;
		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr));
		utcp->send(utcp, pkt, sizeof(pkt->hdr));
		break;

	case ESTABLISHED:
		break;

	case FIN_WAIT_1:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
		// Send unacked data again.
		pkt->hdr.seq = c->snd.una;
		pkt->hdr.ack = c->rcv.nxt;
		pkt->hdr.ctl = ACK;
		uint32_t len = min(seqdiff(c->snd.last, c->snd.una), utcp->mss);

		if(fin_wanted(c, c->snd.una + len)) {
			len--;
			pkt->hdr.ctl |= FIN;
		} else {
			break;
		}

		assert(len == 0);

		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr) + len);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + len);
		break;

	case CLOSED:
	case LISTEN:
	case TIME_WAIT:
	case FIN_WAIT_2:
		// We shouldn't need to retransmit anything in this state.
#ifdef UTCP_DEBUG
		abort();
#endif
		stop_retransmit_timer(c);
		goto cleanup;
	}

	start_retransmit_timer(c);
	c->rto *= 2;

	if(c->rto > MAX_RTO) {
		c->rto = MAX_RTO;
	}

	c->rtt_start.tv_sec = 0; // invalidate RTT timer
	c->dupack = 0; // cancel any ongoing fast recovery

cleanup:
	return;
}

static void handle_unreliable(struct utcp_connection *c, const struct hdr *hdr, const void *data, size_t len) {
	// Fast path for unfragmented packets
	if(!hdr->wnd && !(hdr->ctl & MF)) {
		if(c->recv) {
			c->recv(c, data, len);
		}

		c->rcv.nxt = hdr->seq + len;
		return;
	}
}

static void handle_incoming_data(struct utcp_connection *c, const struct hdr *hdr, const void *data, size_t len) {
	handle_unreliable(c, hdr, data, len);
}

ssize_t utcp_recv(struct utcp *utcp, const void *data, size_t len) {
	const uint8_t *ptr = data;

	if(!utcp) {
		errno = EFAULT;
		return -1;
	}

	if(!len) {
		return 0;
	}

	if(!data) {
		errno = EFAULT;
		return -1;
	}

	// Drop packets smaller than the header

	struct hdr hdr;

	if(len < sizeof(hdr)) {
		print_packet(NULL, "recv", data, len);
		errno = EBADMSG;
		return -1;
	}

	// Make a copy from the potentially unaligned data to a struct hdr

	memcpy(&hdr, ptr, sizeof(hdr));

	// Try to match the packet to an existing connection

	struct utcp_connection *c = find_connection(utcp, hdr.dst, hdr.src);
	print_packet(c, "recv", data, len);

	// Process the header

	ptr += sizeof(hdr);
	len -= sizeof(hdr);

	// Drop packets with an unknown CTL flag

	if(hdr.ctl & ~(SYN | ACK | RST | FIN | MF)) {
		print_packet(NULL, "recv", data, len);
		errno = EBADMSG;
		return -1;
	}

	// Check for auxiliary headers

	const uint8_t *init = NULL;

	uint16_t aux = hdr.aux;

	while(aux) {
		size_t auxlen = 4 * (aux >> 8) & 0xf;
		uint8_t auxtype = aux & 0xff;

		if(len < auxlen) {
			errno = EBADMSG;
			return -1;
		}

		switch(auxtype) {
		case AUX_INIT:
			if(!(hdr.ctl & SYN) || auxlen != 4) {
				errno = EBADMSG;
				return -1;
			}

			init = ptr;
			break;

		default:
			errno = EBADMSG;
			return -1;
		}

		len -= auxlen;
		ptr += auxlen;

		if(!(aux & 0x800)) {
			break;
		}

		if(len < 2) {
			errno = EBADMSG;
			return -1;
		}

		memcpy(&aux, ptr, 2);
		len -= 2;
		ptr += 2;
	}

	// Is it for a new connection?

	if(!c) {
		// Ignore RST packets

		if(hdr.ctl & RST) {
			return 0;
		}

		// Is it a SYN packet and are we LISTENing?

		if(hdr.ctl & SYN && !(hdr.ctl & ACK) && utcp->accept) {
			// If we don't want to accept it, send a RST back
			if((utcp->listen && !utcp->listen(utcp, hdr.dst))) {
				len = 1;
				goto reset;
			}

			// Try to allocate memory, otherwise send a RST back
			c = allocate_connection(utcp, hdr.dst, hdr.src);

			if(!c) {
				len = 1;
				goto reset;
			}

			// Parse auxilliary information
			if(init) {
				if(init[0] < 1) {
					len = 1;
					goto reset;
				}

				c->flags = init[3] & 0x7;
			} else {
				c->flags = UTCP_UDP;
			}

synack:
			// Return SYN+ACK, go to SYN_RECEIVED state
			c->snd.wnd = hdr.wnd;
			c->rcv.irs = hdr.seq;
			c->rcv.nxt = c->rcv.irs + 1;
			set_state(c, SYN_RECEIVED);

			struct {
				struct hdr hdr;
				uint8_t data[4];
			} pkt;

			pkt.hdr.src = c->src;
			pkt.hdr.dst = c->dst;
			pkt.hdr.ack = c->rcv.irs + 1;
			pkt.hdr.seq = c->snd.iss;
			pkt.hdr.wnd = c->utcp->mtu;
			pkt.hdr.ctl = SYN | ACK;

			if(init) {
				pkt.hdr.aux = 0x0101;
				pkt.data[0] = 1;
				pkt.data[1] = 0;
				pkt.data[2] = 0;
				pkt.data[3] = c->flags & 0x7;
				print_packet(c, "send", &pkt, sizeof(hdr) + 4);
				utcp->send(utcp, &pkt, sizeof(hdr) + 4);
			} else {
				pkt.hdr.aux = 0;
				print_packet(c, "send", &pkt, sizeof(hdr));
				utcp->send(utcp, &pkt, sizeof(hdr));
			}

			start_retransmit_timer(c);
		} else {
			// No, we don't want your packets, send a RST back
			len = 1;
			goto reset;
		}

		return 0;
	}

	debug(c, "state %s\n", strstate[c->state]);

	// In case this is for a CLOSED connection, ignore the packet.
	// TODO: make it so incoming packets can never match a CLOSED connection.

	if(c->state == CLOSED) {
		debug(c, "got packet for closed connection\n");
		goto reset;
	}

	// It is for an existing connection.

	// 1. Drop invalid packets.

	// 1a. Drop packets that should not happen in our current state.

	switch(c->state) {
	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		break;

	default:
#ifdef UTCP_DEBUG
		abort();
#endif
		break;
	}

#if UTCP_DEBUG
	int32_t rcv_offset = seqdiff(hdr.seq, c->rcv.nxt);

	if(rcv_offset) {
		debug(c, "packet out of order, offset %u bytes", rcv_offset);
	}

#endif

	c->snd.wnd = hdr.wnd; // TODO: move below

	// 1c. Drop packets with an invalid ACK.
	// ackno should not roll back, and it should also not be bigger than what we ever could have sent
	// (= snd.una + c->sndbuf.used).

	if(hdr.ack != c->snd.last && c->state >= ESTABLISHED) {
		hdr.ack = c->snd.una;
	}

	// 2. Handle RST packets

	if(hdr.ctl & RST) {
		switch(c->state) {
		case SYN_SENT:
			if(!(hdr.ctl & ACK)) {
				return 0;
			}

			// The peer has refused our connection.
			set_state(c, CLOSED);
			errno = ECONNREFUSED;

			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			return 0;

		case SYN_RECEIVED:
			if(hdr.ctl & ACK) {
				return 0;
			}

			// We haven't told the application about this connection yet. Silently delete.
			free_connection(c);
			return 0;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
			if(hdr.ctl & ACK) {
				return 0;
			}

			// The peer has aborted our connection.
			set_state(c, CLOSED);
			errno = ECONNRESET;

			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			return 0;

		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			if(hdr.ctl & ACK) {
				return 0;
			}

			// As far as the application is concerned, the connection has already been closed.
			// If it has called utcp_close() already, we can immediately free this connection.
			if(c->reapable) {
				free_connection(c);
				return 0;
			}

			// Otherwise, immediately move to the CLOSED state.
			set_state(c, CLOSED);
			return 0;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}
	}

	uint32_t advanced;

	if(!(hdr.ctl & ACK)) {
		advanced = 0;
		goto skip_ack;
	}

	// 3. Advance snd.una

	if(seqdiff(hdr.ack, c->snd.last) > 0 || seqdiff(hdr.ack, c->snd.una) < 0) {
		debug(c, "packet ack seqno out of range, %u <= %u < %u\n", c->snd.una, hdr.ack, c->snd.una + c->sndbuf.used);
		goto reset;
	}

	advanced = seqdiff(hdr.ack, c->snd.una);

	if(advanced) {
		// RTT measurement
		if(c->rtt_start.tv_sec) {
			if(c->rtt_seq == hdr.ack) {
				struct timespec now;
				clock_gettime(UTCP_CLOCK, &now);
				int32_t diff = timespec_diff_usec(&now, &c->rtt_start);
				update_rtt(c, diff);
				c->rtt_start.tv_sec = 0;
			} else if(c->rtt_seq < hdr.ack) {
				debug(c, "cancelling RTT measurement: %u < %u\n", c->rtt_seq, hdr.ack);
				c->rtt_start.tv_sec = 0;
			}
		}

		int32_t data_acked = advanced;

		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			data_acked--;
			break;

		// TODO: handle FIN as well.
		default:
			break;
		}

		assert(data_acked >= 0);

#ifndef NDEBUG
		int32_t bufused = seqdiff(c->snd.last, c->snd.una);
		assert(data_acked <= bufused);
#endif

		// Also advance snd.nxt if possible
		if(seqdiff(c->snd.nxt, hdr.ack) < 0) {
			c->snd.nxt = hdr.ack;
		}

		c->snd.una = hdr.ack;

		if(c->dupack) {
			if(c->dupack >= 3) {
				debug(c, "fast recovery ended\n");
				c->snd.cwnd = c->snd.ssthresh;
			}

			c->dupack = 0;
		}

		// Increase the congestion window according to RFC 5681
		if(c->snd.cwnd < c->snd.ssthresh) {
			c->snd.cwnd += min(advanced, utcp->mss); // eq. 2
		} else {
			c->snd.cwnd += max(1, (utcp->mss * utcp->mss) / c->snd.cwnd); // eq. 3
		}

		if(c->snd.cwnd > c->utcp->mtu) {
			c->snd.cwnd = c->utcp->mtu;
		}

		debug_cwnd(c);

		// Check if we have sent a FIN that is now ACKed.
		switch(c->state) {
		case FIN_WAIT_1:
			if(c->snd.una == c->snd.last) {
				set_state(c, FIN_WAIT_2);
			}

			break;

		case CLOSING:
			if(c->snd.una == c->snd.last) {
				clock_gettime(UTCP_CLOCK, &c->conn_timeout);
				c->conn_timeout.tv_sec += utcp->timeout;
				set_state(c, TIME_WAIT);
			}

			break;

		default:
			break;
		}
	}

	// 4. Update timers

	if(advanced) {
		if(c->snd.una == c->snd.last) {
			stop_retransmit_timer(c);
			timespec_clear(&c->conn_timeout);
		}
	}

skip_ack:
	// 5. Process SYN stuff

	if(hdr.ctl & SYN) {
		switch(c->state) {
		case SYN_SENT:

			// This is a SYNACK. It should always have ACKed the SYN.
			if(!advanced) {
				goto reset;
			}

			c->rcv.irs = hdr.seq;
			c->rcv.nxt = hdr.seq + 1;

			if(c->shut_wr) {
				c->snd.last++;
				set_state(c, FIN_WAIT_1);
			} else {
				set_state(c, ESTABLISHED);
			}

			break;

		case SYN_RECEIVED:
			// This is a retransmit of a SYN, send back the SYNACK.
			goto synack;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// This could be a retransmission. Ignore the SYN flag, but send an ACK back.
			break;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}
	}

	// 6. Process new data

	if(c->state == SYN_RECEIVED) {
		// This is the ACK after the SYNACK. It should always have ACKed the SYNACK.
		if(!advanced) {
			goto reset;
		}

		// Are we still LISTENing?
		if(utcp->accept) {
			utcp->accept(c, c->src);
		}

		if(c->state != ESTABLISHED) {
			set_state(c, CLOSED);
			c->reapable = true;
			goto reset;
		}
	}

	if(len) {
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;

		case ESTABLISHED:
			break;

		case FIN_WAIT_1:
		case FIN_WAIT_2:
			if(c->reapable) {
				// We already closed the connection and are not interested in more data.
				goto reset;
			}

			break;

		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm no, We should never receive more data after a FIN.
			goto reset;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

		handle_incoming_data(c, &hdr, ptr, len);
	}

	// 7. Process FIN stuff

	if(hdr.ctl & FIN) {
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
#ifdef UTCP_DEBUG
			abort();
#endif
			break;

		case ESTABLISHED:
			set_state(c, CLOSE_WAIT);
			break;

		case FIN_WAIT_1:
			set_state(c, CLOSING);
			break;

		case FIN_WAIT_2:
			clock_gettime(UTCP_CLOCK, &c->conn_timeout);
			c->conn_timeout.tv_sec += utcp->timeout;
			set_state(c, TIME_WAIT);
			break;

		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm, no. We should never receive a second FIN.
			goto reset;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}

		// FIN counts as one sequence number
		c->rcv.nxt++;
		len++;

		// Inform the application that the peer closed its end of the connection.
		if(c->recv) {
			errno = 0;
			c->recv(c, NULL, 0);
		}
	}

	// Now we send something back if:
	// - we received data, so we have to send back an ACK
	//   -> sendatleastone = true
	// - or we got an ack, so we should maybe send a bit more data
	//   -> sendatleastone = false

	if(hdr.ctl & SYN || hdr.ctl & FIN) {
		ack(c, NULL, 0);
	}

	return 0;

reset:
	swap_ports(&hdr);
	hdr.wnd = 0;
	hdr.aux = 0;

	if(hdr.ctl & ACK) {
		hdr.seq = hdr.ack;
		hdr.ctl = RST;
	} else {
		hdr.ack = hdr.seq + len;
		hdr.seq = 0;
		hdr.ctl = RST | ACK;
	}

	print_packet(c, "send", &hdr, sizeof(hdr));
	utcp->send(utcp, &hdr, sizeof(hdr));
	return 0;

}

int utcp_shutdown(struct utcp_connection *c, int dir) {
	debug(c, "shutdown %d at %u\n", dir, c ? c->snd.last : 0);

	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		debug(c, "shutdown() called on closed connection\n");
		errno = EBADF;
		return -1;
	}

	if(!(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_WR || dir == UTCP_SHUT_RDWR)) {
		errno = EINVAL;
		return -1;
	}

	// TCP does not have a provision for stopping incoming packets.
	// The best we can do is to just ignore them.
	if(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_RDWR) {
		c->recv = NULL;
	}

	// The rest of the code deals with shutting down writes.
	if(dir == UTCP_SHUT_RD) {
		return 0;
	}

	// Only process shutting down writes once.
	if(c->shut_wr) {
		return 0;
	}

	c->shut_wr = true;

	switch(c->state) {
	case CLOSED:
	case LISTEN:
		errno = ENOTCONN;
		return -1;

	case SYN_SENT:
		return 0;

	case SYN_RECEIVED:
	case ESTABLISHED:
		set_state(c, FIN_WAIT_1);
		break;

	case FIN_WAIT_1:
	case FIN_WAIT_2:
		return 0;

	case CLOSE_WAIT:
		set_state(c, CLOSING);
		break;

	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		return 0;
	}

	c->snd.last++;

	ack(c, NULL, 0);

	if(!timespec_isset(&c->rtrx_timeout)) {
		start_retransmit_timer(c);
	}

	return 0;
}

static bool reset_connection(struct utcp_connection *c) {
	if(!c) {
		errno = EFAULT;
		return false;
	}

	if(c->reapable) {
		debug(c, "abort() called on closed connection\n");
		errno = EBADF;
		return false;
	}

	switch(c->state) {
	case CLOSED:
		return true;

	case LISTEN:
	case SYN_SENT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		set_state(c, CLOSED);
		return true;

	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
		set_state(c, CLOSED);
		break;
	}

	// Send RST

	struct hdr hdr;

	hdr.src = c->src;
	hdr.dst = c->dst;
	hdr.seq = c->snd.nxt;
	hdr.ack = c->rcv.nxt;
	hdr.wnd = 0;
	hdr.ctl = RST;
	hdr.aux = 0;

	print_packet(c, "send", &hdr, sizeof(hdr));
	c->utcp->send(c->utcp, &hdr, sizeof(hdr));
	return true;
}

static void set_reapable(struct utcp_connection *c) {
	c->recv = NULL;
	c->reapable = true;
}

// Resets all connections, but does not invalidate connection handles
void utcp_reset_all_connections(struct utcp *utcp) {
	if(!utcp) {
		errno = EINVAL;
		return;
	}

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable || c->state == CLOSED) {
			continue;
		}

		reset_connection(c);

		if(c->recv) {
			errno = 0;
			c->recv(c, NULL, 0);
		}
	}

	return;
}

int utcp_close(struct utcp_connection *c) {
	if(utcp_shutdown(c, SHUT_RDWR) && errno != ENOTCONN) {
		return -1;
	}

	set_reapable(c);
	return 0;
}

int utcp_abort(struct utcp_connection *c) {
	if(!reset_connection(c)) {
		return -1;
	}

	set_reapable(c);
	return 0;
}

/* Handle timeouts.
 * One call to this function will loop through all connections,
 * checking if something needs to be resent or not.
 * The return value is the time to the next timeout in milliseconds,
 * or maybe a negative value if the timeout is infinite.
 */
struct timespec utcp_timeout(struct utcp *utcp) {
	struct timespec now;
	clock_gettime(UTCP_CLOCK, &now);
	struct timespec next = {now.tv_sec + 3600, now.tv_nsec};

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(!c) {
			continue;
		}

		// delete connections that have been utcp_close()d.
		if(c->state == CLOSED) {
			if(c->reapable) {
				debug(c, "reaping\n");
				free_connection(c);
				i--;
			}

			continue;
		}

		if(timespec_isset(&c->conn_timeout) && timespec_lt(&c->conn_timeout, &now)) {
			errno = ETIMEDOUT;
			c->state = CLOSED;

			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			continue;
		}

		if(timespec_isset(&c->rtrx_timeout) && timespec_lt(&c->rtrx_timeout, &now)) {
			debug(c, "retransmitting after timeout\n");
			retransmit(c);
		}

		if(timespec_isset(&c->conn_timeout) && timespec_lt(&c->conn_timeout, &next)) {
			next = c->conn_timeout;
		}

		if(timespec_isset(&c->rtrx_timeout) && timespec_lt(&c->rtrx_timeout, &next)) {
			next = c->rtrx_timeout;
		}
	}

	struct timespec diff;

	timespec_sub(&next, &now, &diff);

	return diff;
}

bool utcp_is_active(struct utcp *utcp) {
	if(!utcp) {
		return false;
	}

	for(int i = 0; i < utcp->nconnections; i++)
		if(utcp->connections[i]->state != CLOSED && utcp->connections[i]->state != TIME_WAIT) {
			return true;
		}

	return false;
}

struct utcp *utcp_init(utcp_accept_t accept, utcp_listen_t listen, utcp_send_t send, void *priv) {
	if(!send) {
		errno = EFAULT;
		return NULL;
	}

	struct utcp *utcp = calloc(1, sizeof(*utcp));

	if(!utcp) {
		return NULL;
	}

	utcp_set_mtu(utcp, DEFAULT_MTU);

	if(!utcp->pkt) {
		free(utcp);
		return NULL;
	}

	if(!CLOCK_GRANULARITY) {
		struct timespec res;
		clock_getres(UTCP_CLOCK, &res);
		CLOCK_GRANULARITY = res.tv_sec * USEC_PER_SEC + res.tv_nsec / 1000;
	}

	utcp->accept = accept;
	utcp->listen = listen;
	utcp->send = send;
	utcp->priv = priv;
	utcp->timeout = DEFAULT_USER_TIMEOUT; // sec

	return utcp;
}

void utcp_exit(struct utcp *utcp) {
	if(!utcp) {
		return;
	}

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(!c->reapable) {
			if(c->recv) {
				c->recv(c, NULL, 0);
			}
		}

		free(c);
	}

	free(utcp->connections);
	free(utcp->pkt);
	free(utcp);
}

uint16_t utcp_get_mtu(struct utcp *utcp) {
	return utcp ? utcp->mtu : 0;
}

uint16_t utcp_get_mss(struct utcp *utcp) {
	return utcp ? utcp->mss : 0;
}

void utcp_set_mtu(struct utcp *utcp, uint16_t mtu) {
	if(!utcp) {
		return;
	}

	if(mtu <= sizeof(struct hdr)) {
		return;
	}

	if(mtu > utcp->mtu) {
		char *new = realloc(utcp->pkt, mtu + sizeof(struct hdr));

		if(!new) {
			return;
		}

		utcp->pkt = new;
	}

	utcp->mtu = mtu;
	utcp->mss = mtu - sizeof(struct hdr);
}

void utcp_reset_timers(struct utcp *utcp) {
	if(!utcp) {
		return;
	}

	struct timespec now, then;

	clock_gettime(UTCP_CLOCK, &now);

	then = now;

	then.tv_sec += utcp->timeout;

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable) {
			continue;
		}

		if(timespec_isset(&c->rtrx_timeout)) {
			c->rtrx_timeout = now;
		}

		if(timespec_isset(&c->conn_timeout)) {
			c->conn_timeout = then;
		}

		c->rtt_start.tv_sec = 0;

		if(c->rto > START_RTO) {
			c->rto = START_RTO;
		}
	}
}

int utcp_get_user_timeout(struct utcp *u) {
	return u ? u->timeout : 0;
}

void utcp_set_user_timeout(struct utcp *u, int timeout) {
	if(u) {
		u->timeout = timeout;
	}
}

bool utcp_get_nodelay(struct utcp_connection *c) {
	return c ? c->nodelay : false;
}

void utcp_set_nodelay(struct utcp_connection *c, bool nodelay) {
	if(c) {
		c->nodelay = nodelay;
	}
}

bool utcp_get_keepalive(struct utcp_connection *c) {
	return c ? c->keepalive : false;
}

void utcp_set_keepalive(struct utcp_connection *c, bool keepalive) {
	if(c) {
		c->keepalive = keepalive;
	}
}

void utcp_set_recv_cb(struct utcp_connection *c, utcp_recv_t recv) {
	if(c) {
		c->recv = recv;
	}
}

void utcp_set_accept_cb(struct utcp *utcp, utcp_accept_t accept, utcp_listen_t listen) {
	if(utcp) {
		utcp->accept = accept;
		utcp->listen = listen;
	}
}

void utcp_expect_data(struct utcp_connection *c, bool expect) {
	if(!c || c->reapable) {
		return;
	}

	if(!(c->state == ESTABLISHED || c->state == FIN_WAIT_1 || c->state == FIN_WAIT_2)) {
		return;
	}

	if(expect) {
		// If we expect data, start the connection timer.
		if(!timespec_isset(&c->conn_timeout)) {
			clock_gettime(UTCP_CLOCK, &c->conn_timeout);
			c->conn_timeout.tv_sec += c->utcp->timeout;
		}
	} else {
		// If we want to cancel expecting data, only clear the timer when there is no unACKed data.
		if(c->snd.una == c->snd.last) {
			timespec_clear(&c->conn_timeout);
		}
	}
}

void utcp_set_flags(struct utcp_connection *c, uint32_t flags) {
	c->flags &= ~UTCP_CHANGEABLE_FLAGS;
	c->flags |= flags & UTCP_CHANGEABLE_FLAGS;
}

void utcp_offline(struct utcp *utcp, bool offline) {
	struct timespec now;
	clock_gettime(UTCP_CLOCK, &now);

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable) {
			continue;
		}

		utcp_expect_data(c, offline);

		if(!offline) {
			if(timespec_isset(&c->rtrx_timeout)) {
				c->rtrx_timeout = now;
			}

			utcp->connections[i]->rtt_start.tv_sec = 0;

			if(c->rto > START_RTO) {
				c->rto = START_RTO;
			}
		}
	}
}

void utcp_set_clock_granularity(long granularity) {
	CLOCK_GRANULARITY = granularity;
}
