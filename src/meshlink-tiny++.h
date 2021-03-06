#ifndef MESHLINKPP_H
#define MESHLINKPP_H

/*
    meshlink-tiny++.h -- MeshLink C++ API
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

#include <meshlink-tiny.h>
#include <new> // for 'placement new'

namespace meshlink {
class mesh;
class node;

/// Severity of log messages generated by MeshLink.
typedef meshlink_log_level_t log_level_t;

/// Code of most recent error encountered.
typedef meshlink_errno_t errno_t;

/// A callback for receiving data from the mesh.
/** @param mesh      A handle which represents an instance of MeshLink.
 *  @param source    A pointer to a meshlink::node describing the source of the data.
 *  @param data      A pointer to a buffer containing the data sent by the source.
 *  @param len       The length of the received data.
 */
typedef void (*receive_cb_t)(mesh *mesh, node *source, const void *data, size_t len);

/// A callback reporting the meta-connection attempt made by the host node to an another node.
/** @param mesh      A handle which represents an instance of MeshLink.
 *  @param node      A pointer to a meshlink_node_t describing the node to whom meta-connection is being tried.
 *                   This pointer is valid until meshlink_close() is called.
 */
typedef void (*connection_try_cb_t)(mesh *mesh, node *node);

/// A callback reporting node status changes.
/** @param mesh       A handle which represents an instance of MeshLink.
 *  @param node       A pointer to a meshlink::node describing the node whose status changed.
 *  @param reachable  True if the node is reachable, false otherwise.
 */
typedef void (*node_status_cb_t)(mesh *mesh, node *node, bool reachable);

/// A callback reporting duplicate node detection.
/** @param mesh       A handle which represents an instance of MeshLink.
 *  @param node       A pointer to a meshlink_node_t describing the node which is duplicate.
 *                    This pointer is valid until meshlink_close() is called.
 */
typedef void (*duplicate_cb_t)(mesh *mesh, node *node);

/// A callback for receiving log messages generated by MeshLink.
/** @param mesh      A handle which represents an instance of MeshLink.
 *  @param level     An enum describing the severity level of the message.
 *  @param text      A pointer to a string containing the textual log message.
 */
typedef void (*log_cb_t)(mesh *mesh, log_level_t level, const char *text);

/// A class describing a MeshLink node.
class node: public meshlink_node_t {
};

/// A class describing a MeshLink mesh.
class mesh {
public:
	mesh() : handle(0) {}

	virtual ~mesh() {
		this->close();
	}

	bool isOpen() const {
		return (handle != 0);
	}

// TODO: please enable C++11 in autoconf to enable "move constructors":
//		mesh(mesh&& other)
//		: handle(other.handle)
//		{
//			if(handle)
//				handle->priv = this;
//			other.handle = 0;
//		}

	/// Initialize MeshLink's configuration directory.
	/** This function causes MeshLink to initialize its configuration directory,
	 *  if it hasn't already been initialized.
	 *  It only has to be run the first time the application starts,
	 *  but it is not a problem if it is run more than once, as long as
	 *  the arguments given are the same.
	 *
	 *  This function does not start any network I/O yet. The application should
	 *  first set callbacks, and then call meshlink_start().
	 *
	 *  @param confbase The directory in which MeshLink will store its configuration files.
	 *  @param name     The name which this instance of the application will use in the mesh.
	 *  @param appname  The application name which will be used in the mesh.
	 *  @param devclass The device class which will be used in the mesh.
	 *
	 *  @return         This function will return a pointer to a meshlink::mesh if MeshLink has successfully set up its configuration files, NULL otherwise.
	 */
	bool open(const char *confbase, const char *name, const char *appname, dev_class_t devclass) {
		handle = meshlink_open(confbase, name, appname, devclass);

		if(handle) {
			handle->priv = this;
		}

		return isOpen();
	}

	mesh(const char *confbase, const char *name, const char *appname, dev_class_t devclass) {
		open(confbase, name, appname, devclass);
	}

	/// Close the MeshLink handle.
	/** This function calls meshlink_stop() if necessary,
	 *  and frees all memory allocated by MeshLink.
	 *  Afterwards, the handle and any pointers to a struct meshlink_node are invalid.
	 */
	void close() {
		if(handle) {
			handle->priv = 0;
			meshlink_close(handle);
		}

		handle = 0;
	}

	/** instead of registerin callbacks you derive your own class and overwrite the following abstract member functions.
	 *  These functions are run in MeshLink's own thread.
	 *  It is therefore important that these functions use apprioriate methods (queues, pipes, locking, etc.)
	 *  to hand the data over to the application's thread.
	 *  These functions should also not block itself and return as quickly as possible.
	 * The default member functions are no-ops, so you are not required to overwrite all these member functions
	 */

	/// This function is called whenever another node sends data to the local node.
	virtual void receive(node *source, const void *data, size_t length) {
		/* do nothing */
		(void)source;
		(void)data;
		(void) length;
	}

	/// This functions is called whenever another node's status changed.
	virtual void node_status(node *peer, bool reachable) {
		/* do nothing */
		(void)peer;
		(void)reachable;
	}

	/// This functions is called whenever a duplicate node is detected.
	virtual void node_duplicate(node *peer) {
		/* do nothing */
		(void)peer;
	}

	/// This functions is called whenever MeshLink has some information to log.
	virtual void log(log_level_t level, const char *message) {
		/* do nothing */
		(void)level;
		(void)message;
	}

	/// This functions is called whenever MeshLink has encountered a serious error.
	virtual void error(meshlink_errno_t meshlink_errno) {
		/* do nothing */
		(void)meshlink_errno;
	}

	/// This functions is called whenever MeshLink a meta-connection attempt is made.
	virtual void connection_try(node *peer) {
		/* do nothing */
		(void)peer;
	}

	/// Start MeshLink.
	/** This function causes MeshLink to open network sockets, make outgoing connections, and
	 *  create a new thread, which will handle all network I/O.
	 *
	 *  @return         This function will return true if MeshLink has successfully started its thread, false otherwise.
	 */
	bool start() {
		meshlink_set_receive_cb(handle, &receive_trampoline);
		meshlink_set_node_status_cb(handle, &node_status_trampoline);
		meshlink_set_node_duplicate_cb(handle, &node_duplicate_trampoline);
		meshlink_set_log_cb(handle, MESHLINK_DEBUG, &log_trampoline);
		meshlink_set_error_cb(handle, &error_trampoline);
		meshlink_set_connection_try_cb(handle, &connection_try_trampoline);
		return meshlink_start(handle);
	}

	/// Stop MeshLink.
	/** This function causes MeshLink to disconnect from all other nodes,
	 *  close all sockets, and shut down its own thread.
	 */
	void stop() {
		meshlink_stop(handle);
	}

	/// Send data to another node.
	/** This functions sends one packet of data to another node in the mesh.
	 *  The packet is sent using UDP semantics, which means that
	 *  the packet is sent as one unit and is received as one unit,
	 *  and that there is no guarantee that the packet will arrive at the destination.
	 *  The application should take care of getting an acknowledgement and retransmission if necessary.
	 *
	 *  @param destination  A pointer to a meshlink::node describing the destination for the data.
	 *  @param data         A pointer to a buffer containing the data to be sent to the source.
	 *  @param len          The length of the data.
	 *  @return             This function will return true if MeshLink has queued the message for transmission, and false otherwise.
	 *                      A return value of true does not guarantee that the message will actually arrive at the destination.
	 */
	bool send(node *destination, const void *data, unsigned int len) {
		return meshlink_send(handle, destination, data, len);
	}

	/// Get a handle for a specific node.
	/** This function returns a handle for the node with the given name.
	 *
	 *  @param name         The name of the node for which a handle is requested.
	 *
	 *  @return             A pointer to a meshlink::node which represents the requested node,
	 *                      or NULL if the requested node does not exist.
	 */
	node *get_node(const char *name) {
		return (node *)meshlink_get_node(handle, name);
	}

	/// Get a handle for our own node.
	/** This function returns a handle for the local node.
	 *
	 *  @return             A pointer to a meshlink::node which represents the local node.
	 */
	node *get_self() {
		return (node *)meshlink_get_self(handle);
	}

	/// Get a list of all nodes.
	/** This function returns a list with handles for all known nodes.
	 *
	 *  @param nodes        A pointer to an array of pointers to meshlink::node, which should be allocated by the application.
	 *  @param nmemb        The maximum number of pointers that can be stored in the nodes array.
	 *
	 *  @return             The number of known nodes, or -1 in case of an error.
	 *                      This can be larger than nmemb, in which case not all nodes were stored in the nodes array.
	 */
	node **get_all_nodes(node **nodes, size_t *nmemb) {
		return (node **)meshlink_get_all_nodes(handle, (meshlink_node_t **)nodes, nmemb);
	}

	/// Sign data using the local node's MeshLink key.
	/** This function signs data using the local node's MeshLink key.
	 *  The generated signature can be securely verified by other nodes.
	 *
	 *  @param data         A pointer to a buffer containing the data to be signed.
	 *  @param len          The length of the data to be signed.
	 *  @param signature    A pointer to a buffer where the signature will be stored.
	 *  @param siglen       The size of the signature buffer. Will be changed after the call to match the size of the signature itself.
	 *
	 *  @return             This function returns true if the signature is valid, false otherwise.
	 */
	bool sign(const void *data, size_t len, void *signature, size_t *siglen) {
		return meshlink_sign(handle, data, len, signature, siglen);
	}

	/// Verify the signature generated by another node of a piece of data.
	/** This function verifies the signature that another node generated for a piece of data.
	 *
	 *  @param source       A pointer to a meshlink_node_t describing the source of the signature.
	 *  @param data         A pointer to a buffer containing the data to be verified.
	 *  @param len          The length of the data to be verified.
	 *  @param signature    A pointer to a string containing the signature.
	 *  @param siglen       The size of the signature.
	 *
	 *  @return             This function returns true if the signature is valid, false otherwise.
	 */
	bool verify(node *source, const void *data, size_t len, const void *signature, size_t siglen) {
		return meshlink_verify(handle, source, data, len, signature, siglen);
	}

	/// Set the canonical Address for a node.
	/** This function sets the canonical Address for a node.
	 *  This address is stored permanently until it is changed by another call to this function,
	 *  unlike other addresses associated with a node,
	 *  such as those added with meshlink_hint_address() or addresses discovered at runtime.
	 *
	 *  If a canonical Address is set for the local node,
	 *  it will be used for the hostname part of generated invitation URLs.
	 *
	 *  @param node         A pointer to a meshlink_node_t describing the node.
	 *  @param address      A nul-terminated C string containing the address, which can be either in numeric format or a hostname.
	 *  @param port         A nul-terminated C string containing the port, which can be either in numeric or symbolic format.
	 *                      If it is NULL, the listening port's number will be used.
	 *
	 *  @return             This function returns true if the address was added, false otherwise.
	 */
	bool set_canonical_address(node *node, const char *address, const char *port = NULL) {
		return meshlink_set_canonical_address(handle, node, address, port);
	}

	/// Clear the canonical Address for a node.
	/** This function clears the canonical Address for a node.
	 *
	 *  @param node         A pointer to a struct meshlink_node describing the node.
	 *
	 *  @return             This function returns true if the address was removed, false otherwise.
	 */
	bool clear_canonical_address(node *node) {
		return meshlink_clear_canonical_address(handle, node);
	}

	/// Set the scheduling granularity of the application
	/** This should be set to the effective scheduling granularity for the application.
	 *  This depends on the scheduling granularity of the operating system, the application's
	 *  process priority and whether it is running as realtime or not.
	 *  The default value is 10000 (10 milliseconds).
	 *
	 *  @param granularity  The scheduling granularity of the application in microseconds.
	 */
	void set_granularity(long granularity) {
		meshlink_set_scheduling_granularity(handle, granularity);
	}

	/// Sets the storage policy used by MeshLink
	/** This sets the policy MeshLink uses when it has new information about nodes.
	 *  By default, all udpates will be stored to disk (unless an ephemeral instance has been opened).
	 *  Setting the policy to MESHLINK_STORAGE_KEYS_ONLY, only updates that contain new keys for nodes
	 *  are stored.
	 *  By setting the policy to MESHLINK_STORAGE_DISABLED, no updates will be stored.
	 *
	 *  @param policy  The storage policy to use.
	 */
	void set_storage_policy(meshlink_storage_policy_t policy) {
		meshlink_set_storage_policy(handle, policy);
	}

	/// Use an invitation to join a mesh.
	/** This function allows the local node to join an existing mesh using an invitation URL generated by another node.
	 *  An invitation can only be used if the local node has never connected to other nodes before.
	 *  After a successfully accepted invitation, the name of the local node may have changed.
	 *
	 *  This function may only be called on a mesh that has not been started yet and which is not already part of an existing mesh.
	 *
	 *  This function is blocking. It can take several seconds before it returns.
	 *  There is no guarantee it will perform a successful join.
	 *  Failures might be caused by temporary network outages, or by the invitation having expired.
	 *
	 *  @param invitation   A string containing the invitation URL.
	 *
	 *  @return             This function returns true if the local node joined the mesh it was invited to, false otherwise.
	 */
	bool join(const char *invitation) {
		return meshlink_join(handle, invitation);
	}

	/// Export the local node's key and addresses.
	/** This function generates a string that contains the local node's public key and one or more IP addresses.
	 *  The application can pass it in some way to another node, which can then import it,
	 *  granting the local node access to the other node's mesh.
	 *
	 *  @return             This function returns a string that contains the exported key and addresses.
	 *                      The application should call free() after it has finished using this string.
	 */
	char *export_key() {
		return meshlink_export(handle);
	}

	/// Import another node's key and addresses.
	/** This function accepts a string containing the exported public key and addresses of another node.
	 *  By importing this data, the local node grants the other node access to its mesh.
	 *
	 *  @param data         A string containing the other node's exported key and addresses.
	 *
	 *  @return             This function returns true if the data was valid and the other node has been granted access to the mesh, false otherwise.
	 */
	bool import_key(const char *data) {
		return meshlink_import(handle, data);
	}

	/// Forget any information about a node.
	/** This function allows the local node to forget any information it has about a node,
	 *  and if possible will remove any data it has stored on disk about the node.
	 *
	 *  After this call returns, the node handle is invalid and may no longer be used, regardless
	 *  of the return value of this call.
	 *
	 *  Note that this function does not prevent MeshLink from actually forgetting about a node,
	 *  or re-learning information about a node at a later point in time. It is merely a hint that
	 *  the application does not care about this node anymore and that any resources kept could be
	 *  cleaned up.
	 *
	 *  \memberof meshlink_node
	 *  @param node         A pointer to a struct meshlink_node describing the node to be forgotten.
	 *
	 *  @return             This function returns true if all currently known data about the node has been forgotten, false otherwise.
	 */
	bool forget_node(node *node) {
		return meshlink_forget_node(handle, node);
	}

	/// Inform MeshLink that the local network configuration might have changed
	/** This is intended to be used when there is no way for MeshLink to get notifications of local network changes.
	 *  It forces MeshLink to scan all network interfaces for changes in up/down status and new/removed addresses,
	 *  and will immediately check if all connections to other nodes are still alive.
	 */
	void hint_network_change() {
		meshlink_hint_network_change(handle);
	}

	/// Set device class timeouts
	/** This sets the ping interval and timeout for a given device class.
	 *
	 *  @param devclass      The device class to update
	 *  @param pinginterval  The interval between keepalive packets, in seconds. The default is 60.
	 *  @param pingtimeout   The required time within which a peer should respond, in seconds. The default is 5.
	 *                       The timeout must be smaller than the interval.
	 */
	void set_dev_class_timeouts(dev_class_t devclass, int pinginterval, int pingtimeout) {
		meshlink_set_dev_class_timeouts(handle, devclass, pinginterval, pingtimeout);
	}

	/// Set device class fast retry period
	/** This sets the fast retry period for a given device class.
	 *  During this period after the last time the mesh becomes unreachable, connections are tried once a second.
	 *
	 *  @param devclass           The device class to update
	 *  @param fast_retry_period  The period during which fast connection retries are done. The default is 0.
	 */
	void set_dev_class_fast_retry_period(dev_class_t devclass, int fast_retry_period) {
		meshlink_set_dev_class_fast_retry_period(handle, devclass, fast_retry_period);
	}

	/// Set device class maximum timeout
	/** This sets the maximum timeout for outgoing connection retries for a given device class.
	 *
	 *  @param devclass      The device class to update
	 *  @param maxtimeout    The maximum timeout between reconnection attempts, in seconds. The default is 900.
	 */
	void set_dev_class_maxtimeout(dev_class_t devclass, int maxtimeout) {
		meshlink_set_dev_class_maxtimeout(handle, devclass, maxtimeout);
	}

	/// Set which order invitations are committed
	/** This determines in which order configuration files are written to disk during an invitation.
	 *  By default, the invitee saves the configuration to disk first, then the inviter.
	 *  By calling this function with @a inviter_commits_first set to true, the order is reversed.
	 *
	 *  @param inviter_commits_first  If true, then the node that invited a peer will commit data to disk first.
	 */
	void set_inviter_commits_first(bool inviter_commits_first) {
		meshlink_set_inviter_commits_first(handle, inviter_commits_first);
	}

private:
	// non-copyable:
	mesh(const mesh &) /* TODO: C++11: = delete */;
	void operator=(const mesh &) /* TODO: C++11: = delete */;

	/// static callback trampolines:
	static void receive_trampoline(meshlink_handle_t *handle, meshlink_node_t *source, const void *data, size_t length) {
		if(!(handle->priv)) {
			return;
		}

		meshlink::mesh *that = static_cast<mesh *>(handle->priv);
		that->receive(static_cast<node *>(source), data, length);
	}

	static void node_status_trampoline(meshlink_handle_t *handle, meshlink_node_t *peer, bool reachable) {
		if(!(handle->priv)) {
			return;
		}

		meshlink::mesh *that = static_cast<mesh *>(handle->priv);
		that->node_status(static_cast<node *>(peer), reachable);
	}

	static void node_duplicate_trampoline(meshlink_handle_t *handle, meshlink_node_t *peer) {
		if(!(handle->priv)) {
			return;
		}

		meshlink::mesh *that = static_cast<mesh *>(handle->priv);
		that->node_duplicate(static_cast<node *>(peer));
	}

	static void log_trampoline(meshlink_handle_t *handle, log_level_t level, const char *message) {
		if(!(handle->priv)) {
			return;
		}

		meshlink::mesh *that = static_cast<mesh *>(handle->priv);
		that->log(level, message);
	}

	static void error_trampoline(meshlink_handle_t *handle, meshlink_errno_t meshlink_errno) {
		if(!(handle->priv)) {
			return;
		}

		meshlink::mesh *that = static_cast<mesh *>(handle->priv);
		that->error(meshlink_errno);
	}

	static void connection_try_trampoline(meshlink_handle_t *handle, meshlink_node_t *peer) {
		if(!(handle->priv)) {
			return;
		}

		meshlink::mesh *that = static_cast<mesh *>(handle->priv);
		that->connection_try(static_cast<node *>(peer));
	}

	meshlink_handle_t *handle;
};

static inline const char *strerror(errno_t err = meshlink_errno) {
	return meshlink_strerror(err);
}

/// Destroy a MeshLink instance.
/** This function remove all configuration files of a MeshLink instance. It should only be called when the application
 *  does not have an open handle to this instance. Afterwards, a call to meshlink_open() will create a completely
 *  new instance.
 *
 *  @param confbase The directory in which MeshLink stores its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase @a.
 *
 *  @return         This function will return true if the MeshLink instance was successfully destroyed, false otherwise.
 */
static inline bool destroy(const char *confbase) {
	return meshlink_destroy(confbase);
}
}

#endif
