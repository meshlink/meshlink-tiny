/*
    devtools.c -- Debugging and quality control functions.
    Copyright (C) 2014, 2017 Guus Sliepen <guus@meshlink.io>

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
#include <assert.h>

#include "logger.h"
#include "meshlink_internal.h"
#include "node.h"
#include "submesh.h"
#include "splay_tree.h"
#include "netutl.h"
#include "xalloc.h"

#include "devtools.h"

static void nop_probe(void) {
	return;
}

static void keyrotate_nop_probe(int stage) {
	(void)stage;
	return;
}

static void inviter_commits_first_nop_probe(bool stage) {
	(void)stage;
	return;
}

static void sptps_renewal_nop_probe(meshlink_node_t *node) {
	(void)node;
	return;
}

void (*devtool_trybind_probe)(void) = nop_probe;
void (*devtool_keyrotate_probe)(int stage) = keyrotate_nop_probe;
void (*devtool_set_inviter_commits_first)(bool inviter_commited_first) = inviter_commits_first_nop_probe;
void (*devtool_adns_resolve_probe)(void) = nop_probe;
void (*devtool_sptps_renewal_probe)(meshlink_node_t *node) = sptps_renewal_nop_probe;

void devtool_get_node_status(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status) {
	if(!mesh || !node || !status) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	node_t *internal = (node_t *)node;

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	memcpy(&status->status, &internal->status, sizeof status->status);
	memcpy(&status->address, &internal->address, sizeof status->address);
	status->mtu = internal->mtu;
	status->minmtu = internal->minmtu;
	status->maxmtu = internal->maxmtu;
	status->mtuprobes = internal->mtuprobes;
	status->in_packets = internal->in_packets;
	status->in_bytes = internal->in_bytes;
	status->out_packets = internal->out_packets;
	status->out_bytes = internal->out_bytes;

	// Derive UDP connection status
	if(internal == mesh->self) {
		status->udp_status = DEVTOOL_UDP_WORKING;
	} else if(!internal->status.reachable) {
		status->udp_status = DEVTOOL_UDP_IMPOSSIBLE;
	} else if(!internal->status.validkey) {
		status->udp_status = DEVTOOL_UDP_UNKNOWN;
	} else if(internal->status.udp_confirmed) {
		status->udp_status = DEVTOOL_UDP_WORKING;
	} else if(internal->mtuprobes > 30) {
		status->udp_status = DEVTOOL_UDP_FAILED;
	} else if(internal->mtuprobes > 0) {
		status->udp_status = DEVTOOL_UDP_TRYING;
	} else {
		status->udp_status = DEVTOOL_UDP_UNKNOWN;
	}

	pthread_mutex_unlock(&mesh->mutex);
}

meshlink_submesh_t **devtool_get_all_submeshes(meshlink_handle_t *mesh, meshlink_submesh_t **submeshes, size_t *nmemb) {
	if(!mesh || !nmemb || (*nmemb && !submeshes)) {
		meshlink_errno = MESHLINK_EINVAL;
		return NULL;
	}

	meshlink_submesh_t **result;

	//lock mesh->nodes
	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	*nmemb = mesh->submeshes->count;
	result = realloc(submeshes, *nmemb * sizeof(*submeshes));

	if(result) {
		meshlink_submesh_t **p = result;

		for list_each(submesh_t, s, mesh->submeshes) {
			*p++ = (meshlink_submesh_t *)s;
		}
	} else {
		*nmemb = 0;
		free(submeshes);
		meshlink_errno = MESHLINK_ENOMEM;
	}

	pthread_mutex_unlock(&mesh->mutex);

	return result;
}

meshlink_handle_t *devtool_open_in_netns(const char *confbase, const char *name, const char *appname, dev_class_t devclass, int netns) {
	meshlink_open_params_t *params = meshlink_open_params_init(confbase, name, appname, devclass);
	params->netns = dup(netns);
	meshlink_handle_t *handle;

	if(params->netns == -1) {
		handle = NULL;
		meshlink_errno = MESHLINK_EINVAL;
	} else {
		handle = meshlink_open_ex(params);
	}

	meshlink_open_params_free(params);

	return handle;
}

void devtool_force_sptps_renewal(meshlink_handle_t *mesh, meshlink_node_t *node) {
	if(!mesh || !node) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	node_t *n = (node_t *)node;
	connection_t *c = n->connection;

	n->last_req_key = -3600;

	if(c) {
		c->last_key_renewal = -3600;
	}
}

void devtool_set_meta_status_cb(meshlink_handle_t *mesh, meshlink_node_status_cb_t cb) {
	if(!mesh) {
		meshlink_errno = MESHLINK_EINVAL;
		return;
	}

	if(pthread_mutex_lock(&mesh->mutex) != 0) {
		abort();
	}

	mesh->meta_status_cb = cb;
	pthread_mutex_unlock(&mesh->mutex);
}
