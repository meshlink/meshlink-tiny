#ifndef MESHLINK_DEVTOOLS_H
#define MESHLINK_DEVTOOLS_H

/*
    devtools.h -- header for devtools.h
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

/// \file devtools.h
/** This header files declares functions that are only intended for debugging and quality control.
 *  They are not necessary for the normal operation of MeshLink.
 *  Applications should not depend on any of these functions for their normal operation.
 */

/// The status of a node.
typedef struct devtool_node_status devtool_node_status_t;

/// The status of a node.
struct devtool_node_status {
	uint32_t status;
	uint16_t mtu;
	uint16_t minmtu;
	uint16_t maxmtu;
	int mtuprobes;
	enum {
		DEVTOOL_UDP_FAILED = -2,     /// UDP tried but failed
		DEVTOOL_UDP_IMPOSSIBLE = -1, /// UDP not possible (node unreachable)
		DEVTOOL_UDP_UNKNOWN = 0,     /// UDP status not known (never tried to communicate with the node)
		DEVTOOL_UDP_TRYING,          /// UDP detection in progress
		DEVTOOL_UDP_WORKING,         /// UDP communication established
	} udp_status;
	uint64_t in_packets;
	uint64_t in_bytes;
	uint64_t out_packets;
	uint64_t out_bytes;
};

/// Get the status of a node.
/** This function returns a struct containing extra information about a node.
 *  The information is a snapshot taken at call time.
 *
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a meshlink_node_t.
 *  @param status       A pointer to a devtools_node_status_t variable that has
 *                      to be provided by the caller.
 *                      The contents of this variable will be changed to reflect
 *                      the current status of the node.
 */
void devtool_get_node_status(meshlink_handle_t *mesh, meshlink_node_t *node, devtool_node_status_t *status);

/// Open a MeshLink instance in a given network namespace.
/** This function opens MeshLink in the given network namespace.
 *
 *  @param confbase The directory in which MeshLink will store its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase @a.
 *  @param name     The name which this instance of the application will use in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name @a.
 *  @param appname  The application name which will be used in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name @a.
 *  @param devclass The device class which will be used in the mesh.
 *  @param netns    A filedescriptor that represents the network namespace.
 *
 *  @return         A pointer to a meshlink_handle_t which represents this instance of MeshLink, or NULL in case of an error.
 *                  The pointer is valid until meshlink_close() is called.
 */
meshlink_handle_t *devtool_open_in_netns(const char *confbase, const char *name, const char *appname, dev_class_t devclass, int netns);

/// Debug function pointer variable for set port API
/** This function pointer variable is a userspace tracepoint or debugger callback for
 *  set port function @a meshlink_set_port @a.
 *  On assigning a debug function variable invokes callback when try_bind() succeeds in meshlink_set_port API.
 *
 */
extern void (*devtool_trybind_probe)(void);

/// Debug function pointer variable for encrypted key rotate API
/** This function pointer variable is a userspace tracepoint or debugger callback for
 *  encrypted key rotation function @a meshlink_encrypted_key_rotate @a.
 *  On assigning a debug function variable invokes callback for each stage from the key rotate API.
 *
 *  @param stage Debug stage number.
 */
extern void (*devtool_keyrotate_probe)(int stage);

/// Debug function pointer variable for SPTPS key renewal
/** This function pointer variable is a userspace tracepoint or debugger callback for
 *  SPTPS key renewal.
 *
 *  @param node The node whose SPTPS key(s) are being renewed
 */
extern void (*devtool_sptps_renewal_probe)(meshlink_node_t *node);

/// Force renewal of SPTPS sessions with the given node.
/** This causes the SPTPS sessions for both the UDP and TCP connections to renew their keys.
 *
 *  @param mesh A handle which represents an instance of MeshLink.
 *  @param node The node whose SPTPS key(s) should be renewed
 */
void devtool_force_sptps_renewal(meshlink_handle_t *mesh, meshlink_node_t *node);

/// Debug function pointer variable for asserting inviter/invitee committing sequence
/** This function pointer variable is a userspace tracepoint or debugger callback which
 *  invokes either after inviter writing invitees host file into the disk
 *  or after invitee writing it's main config file and host config files that inviter sent into
 *  the disk.
 *
 *  @param inviter_commited_first       true if inviter committed first else false if invitee committed first the other host file into the disk.
 */
extern void (*devtool_set_inviter_commits_first)(bool inviter_commited_first);

/// Set the meta-connection status callback.
/** This functions sets the callback that is called whenever a meta-connection is made or closed.
 *  The callback is run in MeshLink's own thread.
 *  It is therefore important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink.
 *  @param cb        A pointer to the function which will be called when a node's meta-connection status changes.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void devtool_set_meta_status_cb(struct meshlink_handle *mesh, meshlink_node_status_cb_t cb);

#endif
