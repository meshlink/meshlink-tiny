#ifndef MESHLINK_H
#define MESHLINK_H

/*
    meshlink-tiny.h -- MeshLink API
    Copyright (C) 2014-2021 Guus Sliepen <guus@meshlink.io>

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

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// The length in bytes of a signature made with meshlink_sign()
#define MESHLINK_SIGLEN (64ul)

// The maximum length of fingerprints
#define MESHLINK_FINGERPRINTLEN (64ul)

/// A handle for an instance of MeshLink.
typedef struct meshlink_handle meshlink_handle_t;

/// A handle for a MeshLink node.
typedef struct meshlink_node meshlink_node_t;

/// A struct containing all parameters used for opening a mesh.
typedef struct meshlink_open_params meshlink_open_params_t;

/// Code of most recent error encountered.
typedef enum {
	MESHLINK_OK,           ///< Everything is fine
	MESHLINK_EINVAL,       ///< Invalid parameter(s) to function call
	MESHLINK_ENOMEM,       ///< Out of memory
	MESHLINK_ENOENT,       ///< Node is not known
	MESHLINK_EEXIST,       ///< Node already exists
	MESHLINK_EINTERNAL,    ///< MeshLink internal error
	MESHLINK_ERESOLV,      ///< MeshLink could not resolve a hostname
	MESHLINK_ESTORAGE,     ///< MeshLink could not load or write data from/to disk
	MESHLINK_ENETWORK,     ///< MeshLink encountered a network error
	MESHLINK_EPEER,        ///< A peer caused an error
	MESHLINK_ENOTSUP,      ///< The operation is not supported in the current configuration of MeshLink
	MESHLINK_EBUSY,        ///< The MeshLink instance is already in use by another process
	MESHLINK_EBLACKLISTED  ///< The operation is not allowed because the node is blacklisted
} meshlink_errno_t;

/// Device class
typedef enum {
	DEV_CLASS_BACKBONE = 0,
	DEV_CLASS_STATIONARY = 1,
	DEV_CLASS_PORTABLE = 2,
	DEV_CLASS_UNKNOWN = 3,
	DEV_CLASS_COUNT
} dev_class_t;

/// Storage policy
typedef enum {
	MESHLINK_STORAGE_ENABLED,    ///< Store all updates.
	MESHLINK_STORAGE_DISABLED,   ///< Don't store any updates.
	MESHLINK_STORAGE_KEYS_ONLY   ///< Only store updates when a node's key has changed.
} meshlink_storage_policy_t;

/// Invitation flags
static const uint32_t MESHLINK_INVITE_LOCAL = 1;    // Only use local addresses in the URL
static const uint32_t MESHLINK_INVITE_PUBLIC = 2;   // Only use public or canonical addresses in the URL
static const uint32_t MESHLINK_INVITE_IPV4 = 4;     // Only use IPv4 addresses in the URL
static const uint32_t MESHLINK_INVITE_IPV6 = 8;     // Only use IPv6 addresses in the URL
static const uint32_t MESHLINK_INVITE_NUMERIC = 16; // Don't look up hostnames

/// A variable holding the last encountered error from MeshLink.
/** This is a thread local variable that contains the error code of the most recent error
 *  encountered by a MeshLink API function called in the current thread.
 *  The variable is only updated when an error is encountered, and is not reset to MESHLINK_OK
 *  if a function returned successfully.
 */
extern __thread meshlink_errno_t meshlink_errno;

#ifndef MESHLINK_INTERNAL_H

struct meshlink_handle {
	const char *const name; ///< Textual name of ourself. It is stored in a nul-terminated C string, which is allocated by MeshLink.
	void *priv;             ///< Private pointer which may be set freely by the application, and is never used or modified by MeshLink.
};

struct meshlink_node {
	const char *const name; ///< Textual name of this node. It is stored in a nul-terminated C string, which is allocated by MeshLink.
	void *priv;             ///< Private pointer which may be set freely by the application, and is never used or modified by MeshLink.
};

#endif // MESHLINK_INTERNAL_H

/// Get the text for the given MeshLink error code.
/** This function returns a pointer to the string containing the description of the given error code.
 *
 *  @param err      An error code returned by MeshLink.
 *
 *  @return         A pointer to a string containing the description of the error code.
 *                  The pointer is to static storage that is valid for the lifetime of the application.
 *                  This function will always return a valid pointer, even if an invalid error code has been passed.
 */
const char *meshlink_strerror(meshlink_errno_t err) __attribute__((__warn_unused_result__));

/// Create a new meshlink_open_params_t struct.
/** This function allocates and initializes a new meshlink_open_params_t struct that can be passed to meshlink_open_ex().
 *  The resulting struct may be reused for multiple calls to meshlink_open_ex().
 *  After the last use, the application must free this struct using meshlink_open_params_free().
 *
 *  @param confbase The directory in which MeshLink will store its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase.
 *  @param name     The name which this instance of the application will use in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *                  If NULL is passed as the name, the name used last time the MeshLink instance was initialized is used.
 *  @param appname  The application name which will be used in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *  @param devclass The device class which will be used in the mesh.
 *
 *  @return         A pointer to a meshlink_open_params_t which can be passed to meshlink_open_ex(), or NULL in case of an error.
 *                  The pointer is valid until meshlink_open_params_free() is called.
 */
meshlink_open_params_t *meshlink_open_params_init(const char *confbase, const char *name, const char *appname, dev_class_t devclass) __attribute__((__warn_unused_result__));

/// Free a meshlink_open_params_t struct.
/** This function frees a meshlink_open_params_t struct and all resources associated with it.
 *
 *  @param params   A pointer to a meshlink_open_params_t which must have been created earlier with meshlink_open_params_init().
 */
void meshlink_open_params_free(meshlink_open_params_t *params);

/// Set the network namespace MeshLink should use.
/** This function changes the open parameters to use the given netns filedescriptor.
 *
 *  @param params   A pointer to a meshlink_open_params_t which must have been created earlier with meshlink_open_params_init().
 *  @param netns    A filedescriptor that must point to a valid network namespace, or -1 to have MeshLink use the same namespace as the calling thread.
 *
 *  @return         This function will return true if the open parameters have been successfully updated, false otherwise.
 */
bool meshlink_open_params_set_netns(meshlink_open_params_t *params, int netns) __attribute__((__warn_unused_result__));

/// Set the encryption key MeshLink should use for local storage.
/** This function changes the open parameters to use the given key for encrypting MeshLink's own configuration files.
 *
 *  @param params   A pointer to a meshlink_open_params_t which must have been created earlier with meshlink_open_params_init().
 *  @param key      A pointer to a key, or NULL in case no encryption should be used.
 *  @param keylen   The length of the given key, or 0 in case no encryption should be used.
 *
 *  @return         This function will return true if the open parameters have been successfully updated, false otherwise.
 */
bool meshlink_open_params_set_storage_key(meshlink_open_params_t *params, const void *key, size_t keylen) __attribute__((__warn_unused_result__));

/// Set the encryption key MeshLink should use for local storage.
/** This function changes the open parameters to use the given storage policy.
 *
 *  @param params   A pointer to a meshlink_open_params_t which must have been created earlier with meshlink_open_params_init().
 *  @param policy   The storage policy to use.
 *
 *  @return         This function will return true if the open parameters have been successfully updated, false otherwise.
 */
bool meshlink_open_params_set_storage_policy(meshlink_open_params_t *params, meshlink_storage_policy_t policy) __attribute__((__warn_unused_result__));

/// Set the filename of the lockfile.
/** This function changes the path of the lockfile used to ensure only one instance of MeshLink can be open at the same time.
 *  If an application changes this, it must always set it to the same location.
 *
 *  @param params   A pointer to a meshlink_open_params_t which must have been created earlier with meshlink_open_params_init().
 *  @param filename The filename of the lockfile.
 *
 *  @return         This function will return true if the open parameters have been successfully updated, false otherwise.
 */
bool meshlink_open_params_set_lock_filename(meshlink_open_params_t *params, const char *filename) __attribute__((__warn_unused_result__));

/// Open or create a MeshLink instance.
/** This function opens or creates a MeshLink instance.
 *  All parameters needed by MeshLink are passed via a meshlink_open_params_t struct,
 *  which must have been initialized earlier by the application.
 *
 *  This function returns a pointer to a struct meshlink_handle that will be allocated by MeshLink.
 *  When the application does no longer need to use this handle, it must call meshlink_close() to
 *  free its resources.
 *
 *  This function does not start any network I/O yet. The application should
 *  first set callbacks, and then call meshlink_start().
 *
 *  @param params   A pointer to a meshlink_open_params_t which must be filled in by the application.
 *                  After the function returns, the application is free to reuse or free @a params.
 *
 *  @return         A pointer to a struct meshlink_handle which represents this instance of MeshLink, or NULL in case of an error.
 *                  The pointer is valid until meshlink_close() is called.
 */
struct meshlink_handle *meshlink_open_ex(const meshlink_open_params_t *params) __attribute__((__warn_unused_result__));

/// Open or create a MeshLink instance.
/** This function opens or creates a MeshLink instance.
 *  The state is stored in the configuration directory passed in the variable @a confbase.
 *  If the configuration directory does not exist yet, for example when it is the first time
 *  this instance is opened, the configuration directory will be automatically created and initialized.
 *  However, the parent directory should already exist, otherwise an error will be returned.
 *
 *  The name given should be a unique identifier for this instance.
 *
 *  This function returns a pointer to a struct meshlink_handle that will be allocated by MeshLink.
 *  When the application does no longer need to use this handle, it must call meshlink_close() to
 *  free its resources.
 *
 *  This function does not start any network I/O yet. The application should
 *  first set callbacks, and then call meshlink_start().
 *
 *  @param confbase The directory in which MeshLink will store its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase.
 *  @param name     The name which this instance of the application will use in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *                  If NULL is passed as the name, the name used last time the MeshLink instance was initialized is used.
 *  @param appname  The application name which will be used in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *  @param devclass The device class which will be used in the mesh.
 *
 *  @return         A pointer to a struct meshlink_handle which represents this instance of MeshLink, or NULL in case of an error.
 *                  The pointer is valid until meshlink_close() is called.
 */
struct meshlink_handle *meshlink_open(const char *confbase, const char *name, const char *appname, dev_class_t devclass) __attribute__((__warn_unused_result__));

/// Open or create a MeshLink instance that uses encrypted storage.
/** This function opens or creates a MeshLink instance.
 *  The state is stored in the configuration directory passed in the variable @a confbase.
 *  If the configuration directory does not exist yet, for example when it is the first time
 *  this instance is opened, the configuration directory will be automatically created and initialized.
 *  However, the parent directory should already exist, otherwise an error will be returned.
 *
 *  The name given should be a unique identifier for this instance.
 *
 *  This function returns a pointer to a struct meshlink_handle that will be allocated by MeshLink.
 *  When the application does no longer need to use this handle, it must call meshlink_close() to
 *  free its resources.
 *
 *  This function does not start any network I/O yet. The application should
 *  first set callbacks, and then call meshlink_start().
 *
 *  @param confbase The directory in which MeshLink will store its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase.
 *  @param name     The name which this instance of the application will use in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *                  If NULL is passed as the name, the name used last time the MeshLink instance was initialized is used.
 *  @param appname  The application name which will be used in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *  @param devclass The device class which will be used in the mesh.
 *  @param key      A pointer to a key used to encrypt storage.
 *  @param keylen   The length of the key in bytes.
 *
 *  @return         A pointer to a struct meshlink_handle which represents this instance of MeshLink, or NULL in case of an error.
 *                  The pointer is valid until meshlink_close() is called.
 */
struct meshlink_handle *meshlink_open_encrypted(const char *confbase, const char *name, const char *appname, dev_class_t devclass, const void *key, size_t keylen) __attribute__((__warn_unused_result__));

/// Create an ephemeral MeshLink instance that does not store any state.
/** This function creates a MeshLink instance.
 *  No state is ever saved, so once this instance is closed, all its state is gone.
 *
 *  The name given should be a unique identifier for this instance.
 *
 *  This function returns a pointer to a struct meshlink_handle that will be allocated by MeshLink.
 *  When the application does no longer need to use this handle, it must call meshlink_close() to
 *  free its resources.
 *
 *  This function does not start any network I/O yet. The application should
 *  first set callbacks, and then call meshlink_start().
 *
 *  @param name     The name which this instance of the application will use in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *  @param appname  The application name which will be used in the mesh.
 *                  After the function returns, the application is free to overwrite or free @a name.
 *  @param devclass The device class which will be used in the mesh.
 *
 *  @return         A pointer to a struct meshlink_handle which represents this instance of MeshLink, or NULL in case of an error.
 *                  The pointer is valid until meshlink_close() is called.
 */
struct meshlink_handle *meshlink_open_ephemeral(const char *name, const char *appname, dev_class_t devclass) __attribute__((__warn_unused_result__));

/// Start MeshLink.
/** This function causes MeshLink to open network sockets, make outgoing connections, and
 *  create a new thread, which will handle all network I/O.
 *
 *  It is allowed to call this function even if MeshLink is already started, in which case it will return true.
 *
 *  \memberof meshlink_handle
 *  @param mesh     A handle which represents an instance of MeshLink.
 *
 *  @return         This function will return true if MeshLink has successfully started, false otherwise.
 */
bool meshlink_start(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));

/// Stop MeshLink.
/** This function causes MeshLink to disconnect from all other nodes,
 *  close all sockets, and shut down its own thread.
 *
 *  This function always succeeds. It is allowed to call meshlink_stop() even if MeshLink is already stopped or has never been started.
 *
 *  \memberof meshlink_handle
 *  @param mesh     A handle which represents an instance of MeshLink.
 */
void meshlink_stop(struct meshlink_handle *mesh);

/// Close the MeshLink handle.
/** This function calls meshlink_stop() if necessary,
 *  and frees the struct meshlink_handle and all associacted memory allocated by MeshLink.
 *  Afterwards, the handle and any pointers to a struct meshlink_node are invalid.
 *
 *  It is allowed to call this function at any time on a valid handle, except inside callback functions.
 *  If called at a proper time with a valid handle, this function always succeeds.
 *  If called within a callback or with an invalid handle, the result is undefined.
 *
 * \memberof meshlink_handle
 *  @param mesh     A handle which represents an instance of MeshLink.
 */
void meshlink_close(struct meshlink_handle *mesh);

/// Destroy a MeshLink instance.
/** This function remove all configuration files of a MeshLink instance. It should only be called when the application
 *  does not have an open handle to this instance. Afterwards, a call to meshlink_open() will create a completely
 *  new instance.
 *
 *  @param confbase The directory in which MeshLink stores its configuration files.
 *                  After the function returns, the application is free to overwrite or free @a confbase.
 *
 *  @return         This function will return true if the MeshLink instance was successfully destroyed, false otherwise.
 */
bool meshlink_destroy(const char *confbase) __attribute__((__warn_unused_result__));

/// Destroy a MeshLink instance using open parameters.
/** This function remove all configuration files of a MeshLink instance. It should only be called when the application
 *  does not have an open handle to this instance. Afterwards, a call to meshlink_open() will create a completely
 *  new instance.
 *
 *  This version expects a pointer to meshlink_open_params_t,
 *  and will use exactly the same settings used for opening a handle to destroy it.
 *
 *  @param params   A pointer to a meshlink_open_params_t which must be filled in by the application.
 *                  After the function returns, the application is free to reuse or free @a params.
 *
 *  @return         This function will return true if the MeshLink instance was successfully destroyed, false otherwise.
 */
bool meshlink_destroy_ex(const meshlink_open_params_t *params) __attribute__((__warn_unused_result__));

/// A callback for receiving data from the mesh.
/** @param mesh      A handle which represents an instance of MeshLink.
 *  @param source    A pointer to a struct meshlink_node describing the source of the data.
 *  @param data      A pointer to a buffer containing the data sent by the source, or NULL in case there is no data (an empty packet was received).
 *                   The pointer is only valid during the lifetime of the callback.
 *                   The callback should mempcy() the data if it needs to be available outside the callback.
 *  @param len       The length of the received data, or 0 in case there is no data.
 */
typedef void (*meshlink_receive_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *source, const void *data, size_t len);

/// Set the receive callback.
/** This functions sets the callback that is called whenever another node sends data to the local node.
 *  The callback is run in MeshLink's own thread.
 *  It is therefore important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink.
 *  @param cb        A pointer to the function which will be called when another node sends data to the local node.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void meshlink_set_receive_cb(struct meshlink_handle *mesh, meshlink_receive_cb_t cb);

/// A callback reporting the meta-connection attempt made by the host node to an another node.
/** @param mesh      A handle which represents an instance of MeshLink.
 *  @param node      A pointer to a struct meshlink_node describing the node to whom meta-connection is being tried.
 *                   This pointer is valid until meshlink_close() is called.
 */
typedef void (*meshlink_connection_try_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Set the meta-connection try callback.
/** This functions sets the callback that is called whenever a connection attempt is happened to another node.
 *  The callback is run in MeshLink's own thread.
 *  It is therefore important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink.
 *  @param cb        A pointer to the function which will be called when host node attempts to make
 *                   the connection to another node. If a NULL pointer is given, the callback will be disabled.
 */
void meshlink_set_connection_try_cb(struct meshlink_handle *mesh, meshlink_connection_try_cb_t cb);

/// A callback reporting node status changes.
/** @param mesh      A handle which represents an instance of MeshLink.
 *  @param node       A pointer to a struct meshlink_node describing the node whose status changed.
 *                    This pointer is valid until meshlink_close() is called.
 *  @param reachable  True if the node is reachable, false otherwise.
 */
typedef void (*meshlink_node_status_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *node, bool reachable);

/// Set the node status callback.
/** This functions sets the callback that is called whenever another node's status changed.
 *  The callback is run in MeshLink's own thread.
 *  It is therefore important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink.
 *  @param cb        A pointer to the function which will be called when another node's status changes.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void meshlink_set_node_status_cb(struct meshlink_handle *mesh, meshlink_node_status_cb_t cb);

/// A callback reporting duplicate node detection.
/** @param mesh       A handle which represents an instance of MeshLink.
 *  @param node       A pointer to a struct meshlink_node describing the node which is duplicate.
 *                    This pointer is valid until meshlink_close() is called.
 */
typedef void (*meshlink_node_duplicate_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Set the node duplicate callback.
/** This functions sets the callback that is called whenever a duplicate node is detected.
 *  The callback is run in MeshLink's own thread.
 *  It is therefore important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink.
 *  @param cb        A pointer to the function which will be called when a duplicate node is detected.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void meshlink_set_node_duplicate_cb(struct meshlink_handle *mesh, meshlink_node_duplicate_cb_t cb);

/// Severity of log messages generated by MeshLink.
typedef enum {
	MESHLINK_DEBUG,    ///< Internal debugging messages. Only useful during application development.
	MESHLINK_INFO,     ///< Informational messages.
	MESHLINK_WARNING,  ///< Warnings which might indicate problems, but which are not real errors.
	MESHLINK_ERROR,    ///< Errors which hamper correct functioning of MeshLink, without causing it to fail completely.
	MESHLINK_CRITICAL  ///< Critical errors which cause MeshLink to fail completely.
} meshlink_log_level_t;

/// A callback for receiving log messages generated by MeshLink.
/** @param mesh      A handle which represents an instance of MeshLink, or NULL.
 *  @param level     An enum describing the severity level of the message.
 *  @param text      A pointer to a nul-terminated C string containing the textual log message.
 *                   This pointer is only valid for the duration of the callback.
 *                   The application must not free() this pointer.
 *                   The application should strdup() the text if it has to be available outside the callback.
 */
typedef void (*meshlink_log_cb_t)(struct meshlink_handle *mesh, meshlink_log_level_t level, const char *text);

/// Set the log callback.
/** This functions sets the callback that is called whenever MeshLink has some information to log.
 *
 *  The @a mesh parameter can either be a valid MeshLink handle, or NULL.
 *  In case it is NULL, the callback will be called for errors that happen outside the context of a valid mesh instance.
 *  Otherwise, it will be called for errors that happen in the context of the given mesh instance.
 *
 *  If @a mesh is not NULL, then the callback is run in MeshLink's own thread.
 *  It is important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  The @a mesh parameter can either be a valid MeshLink handle, or NULL.
 *  In case it is NULL, the callback will be called for errors that happen outside the context of a valid mesh instance.
 *  Otherwise, it will be called for errors that happen in the context of the given mesh instance.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink, or NULL.
 *  @param level     An enum describing the minimum severity level. Debugging information with a lower level will not trigger the callback.
 *  @param cb        A pointer to the function which will be called when another node sends data to the local node.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void meshlink_set_log_cb(struct meshlink_handle *mesh, meshlink_log_level_t level, meshlink_log_cb_t cb);

/// A callback for receiving error conditions encountered by the MeshLink thread.
/** @param mesh      A handle which represents an instance of MeshLink, or NULL.
 *  @param errno     The error code describing what kind of error occurred.
 */
typedef void (*meshlink_error_cb_t)(struct meshlink_handle *mesh, meshlink_errno_t meshlink_errno);

/// Set the error callback.
/** This functions sets the callback that is called whenever the MeshLink thread encounters a serious error.
 *
 *  While most API functions report an error directly to the caller in case something went wrong,
 *  MeshLink also runs a background thread which can encounter error conditions.
 *  Most of them will be dealt with automatically, however there can be errors that will prevent MeshLink from
 *  working correctly. When the callback is called, it means that MeshLink is no longer functioning
 *  as expected. The application should then present an error message and shut down, or perform any other
 *  action it deems appropriate.
 *
 *  The callback is run in MeshLink's own thread.
 *  It is important that the callback uses apprioriate methods (queues, pipes, locking, etc.)
 *  to hand the data over to the application's thread.
 *  The callback should also not block itself and return as quickly as possible.
 *
 *  Even though the callback signals a serious error inside MeshLink, all open handles are still valid,
 *  and the application should close handles in exactly the same it would have to do if the callback
 *  was not called. This must not be done inside the callback itself.
 *
 *  \memberof meshlink_handle
 *  @param mesh      A handle which represents an instance of MeshLink, or NULL.
 *  @param cb        A pointer to the function which will be called when a serious error is encountered.
 *                   If a NULL pointer is given, the callback will be disabled.
 */
void meshlink_set_error_cb(struct meshlink_handle *mesh, meshlink_error_cb_t cb);

/// Send data to another node.
/** This functions sends one packet of data to another node in the mesh.
 *  The packet is sent using UDP semantics, which means that
 *  the packet is sent as one unit and is received as one unit,
 *  and that there is no guarantee that the packet will arrive at the destination.
 *  Packets that are too big to be sent over the network as one unit might be dropped, and this function may return an error if this situation can be detected beforehand.
 *  The application should take care of getting an acknowledgement and retransmission if necessary.
 *
 *  \memberof meshlink_node
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param destination  A pointer to a struct meshlink_node describing the destination for the data.
 *  @param data         A pointer to a buffer containing the data to be sent to the source.
 *                      After meshlink_send() returns, the application is free to overwrite or free this buffer.
 *                      It is valid to specify a NULL pointer, but only if @a len is also 0.
 *  @param len          The length of the data.
 *  @return             This function will return true if MeshLink has queued the message for transmission, and false otherwise.
 *                      A return value of true does not guarantee that the message will actually arrive at the destination.
 */
bool meshlink_send(struct meshlink_handle *mesh, struct meshlink_node *destination, const void *data, size_t len) __attribute__((__warn_unused_result__));

/// Get a handle for our own node.
/** This function returns a handle for the local node.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *
 *  @return             A pointer to a struct meshlink_node which represents the local node.
 *                      The pointer is guaranteed to be valid until meshlink_close() is called.
 */
struct meshlink_node *meshlink_get_self(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));

/// Get a handle for a specific node.
/** This function returns a handle for the node with the given name.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param name         The name of the node for which a handle is requested.
 *                      After this function returns, the application is free to overwrite or free @a name.
 *
 *  @return             A pointer to a struct meshlink_node which represents the requested node,
 *                      or NULL if the requested node does not exist.
 *                      The pointer is guaranteed to be valid until meshlink_close() is called.
 */
struct meshlink_node *meshlink_get_node(struct meshlink_handle *mesh, const char *name) __attribute__((__warn_unused_result__));

/// Get the fingerprint of a node's public key.
/** This function returns a fingerprint of the node's public key.
 *  It should be treated as an opaque blob.
 *
 *  \memberof meshlink_node
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a struct meshlink_node describing the node.
 *
 *  @return             A nul-terminated C string containing the fingerprint of the node's public key in a printable ASCII format.
 *                      The application should call free() after it is done using this string.
 */
char *meshlink_get_fingerprint(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));

/// Get a list of all nodes.
/** This function returns a list with handles for all known nodes.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param nodes        A pointer to a previously allocated array of pointers to struct meshlink_node, or NULL in which case MeshLink will allocate a new array.
 *                      The application can supply an array it allocated itself with malloc, or the return value from the previous call to this function (which is the preferred way).
 *                      The application is allowed to call free() on the array whenever it wishes.
 *                      The pointers in the array are valid until meshlink_close() is called.
 *  @param nmemb        A pointer to a variable holding the number of nodes that are stored in the array.
 *                      In case the @a nodes argument is not NULL, MeshLink might call realloc() on the array to change its size.
 *                      The contents of this variable will be changed to reflect the new size of the array.
 *
 *  @return             A pointer to an array containing pointers to all known nodes, or NULL in case of an error.
 *                      If the @a nodes argument was not NULL, then the return value can either be the same value or a different value.
 *                      If it is a new value, the old value of @a nodes should not be used anymore.
 *                      If the new value is NULL, then the old array will have been freed by MeshLink.
 */
struct meshlink_node **meshlink_get_all_nodes(struct meshlink_handle *mesh, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));

/// Sign data using the local node's MeshLink key.
/** This function signs data using the local node's MeshLink key.
 *  The generated signature can be securely verified by other nodes.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param data         A pointer to a buffer containing the data to be signed.
 *  @param len          The length of the data to be signed.
 *  @param signature    A pointer to a buffer where the signature will be stored.
 *                      The buffer must be allocated by the application, and should be at least MESHLINK_SIGLEN bytes big.
 *                      The signature is a binary blob, and is not nul-terminated.
 *  @param siglen       The size of the signature buffer. Will be changed after the call to match the size of the signature itself.
 *
 *  @return             This function returns true if the signature was correctly generated, false otherwise.
 */
bool meshlink_sign(struct meshlink_handle *mesh, const void *data, size_t len, void *signature, size_t *siglen) __attribute__((__warn_unused_result__));

/// Get the list of all nodes by device class.
/** This function returns a list with handles for all the nodes that matches with the given @a devclass.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param devclass     Device class of the nodes for which the list has to be obtained.
 *  @param nodes        A pointer to a previously allocated array of pointers to struct meshlink_node, or NULL in which case MeshLink will allocate a new array.
 *                      The application can supply an array it allocated itself with malloc, or the return value from the previous call to this function (which is the preferred way).
 *                      The application is allowed to call free() on the array whenever it wishes.
 *                      The pointers in the array are valid until meshlink_close() is called.
 *  @param nmemb        A pointer to a variable holding the number of nodes with the same @a device class that are stored in the array.
 *                      In case the @a nodes argument is not NULL, MeshLink might call realloc() on the array to change its size.
 *                      The contents of this variable will be changed to reflect the new size of the array.
 *
 *  @return             A pointer to an array containing pointers to all known nodes of the given device class, or NULL in case of an error.
 *                      If the @a nodes argument was not NULL, then the return value can either be the same value or a different value.
 *                      If it is a new value, the old value of @a nodes should not be used anymore.
 *                      If the new value is NULL, then the old array will have been freed by MeshLink.
 */
struct meshlink_node **meshlink_get_all_nodes_by_dev_class(struct meshlink_handle *mesh, dev_class_t devclass, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));

/// Get the list of all nodes by time they were last reachable.
/** This function returns a list with handles for all the nodes whose last known reachability time overlaps with the given time range.
 *  If the range includes 0, it will count nodes that were never online.
 *  If start is bigger than end, the result will be inverted.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param start        Start time.
 *  @param end          End time.
 *  @param nodes        A pointer to a previously allocated array of pointers to struct meshlink_node, or NULL in which case MeshLink will allocate a new array.
 *                      The application can supply an array it allocated itself with malloc, or the return value from the previous call to this function (which is the preferred way).
 *                      The application is allowed to call free() on the array whenever it wishes.
 *                      The pointers in the array are valid until meshlink_close() is called.
 *  @param nmemb        A pointer to a variable holding the number of nodes that were reachable within the period given by @a start and @a end.
 *                      In case the @a nodes argument is not NULL, MeshLink might call realloc() on the array to change its size.
 *                      The contents of this variable will be changed to reflect the new size of the array.
 *
 *  @return             A pointer to an array containing pointers to all known nodes that were reachable within the period given by @a start and @a end.
 *                      If the @a nodes argument was not NULL, then the return value can either be the same value or a different value.
 *                      If it is a new value, the old value of @a nodes should not be used anymore.
 *                      If the new value is NULL, then the old array will have been freed by MeshLink.
 */
struct meshlink_node **meshlink_get_all_nodes_by_last_reachable(struct meshlink_handle *mesh, time_t start, time_t end, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));

/// Get the node's device class.
/** This function returns the device class of the given node.
 *
 *  \memberof meshlink_node
 *  @param mesh          A handle which represents an instance of MeshLink.
 *  @param node          A pointer to a struct meshlink_node describing the node.
 *
 *  @return              This function returns the device class of the @a node, or -1 in case of an error.
 */
dev_class_t meshlink_get_node_dev_class(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));

/// Get a node's reachability status.
/** This function returns the current reachability of a given node, and the times of the last state changes.
 *  If a given state change never happened, the time returned will be 0.
 *
 *  \memberof meshlink_node
 *  @param mesh              A handle which represents an instance of MeshLink.
 *  @param node              A pointer to a struct meshlink_node describing the node.
 *  @param last_reachable    A pointer to a time_t variable that will be filled in with the last time the node became reachable.
 *                           Pass NULL to not have anything written.
 *  @param last_unreachable  A pointer to a time_t variable that will be filled in with the last time the node became unreachable.
 *                           Pass NULL to not have anything written.
 *
 *  @return                  This function returns true if the node is currently reachable, false otherwise.
 */
bool meshlink_get_node_reachability(struct meshlink_handle *mesh, struct meshlink_node *node, time_t *last_reachable, time_t *last_unreachable);

/// Verify the signature generated by another node of a piece of data.
/** This function verifies the signature that another node generated for a piece of data.
 *
 *  \memberof meshlink_node
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param source       A pointer to a struct meshlink_node describing the source of the signature.
 *  @param data         A pointer to a buffer containing the data to be verified.
 *  @param len          The length of the data to be verified.
 *  @param signature    A pointer to a buffer where the signature is stored.
 *  @param siglen       A pointer to a variable holding the size of the signature buffer.
 *                      The contents of the variable will be changed by meshlink_sign() to reflect the actual size of the signature.
 *
 *  @return             This function returns true if the signature is valid, false otherwise.
 */
bool meshlink_verify(struct meshlink_handle *mesh, struct meshlink_node *source, const void *data, size_t len, const void *signature, size_t siglen) __attribute__((__warn_unused_result__));

/// Set the canonical Address for a node.
/** This function sets the canonical Address for a node.
 *  This address is stored permanently until it is changed by another call to this function,
 *  unlike other addresses associated with a node,
 *  such as those added with meshlink_hint_address() or addresses discovered at runtime.
 *
 *  If a canonical Address is set for the local node,
 *  it will be used for the hostname part of generated invitation URLs.
 *  If a canonical Address is set for a remote node,
 *  it is used exclusively for creating outgoing connections to that node.
 *
 *  \memberof meshlink_node
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a struct meshlink_node describing the node.
 *  @param address      A nul-terminated C string containing the address, which can be either in numeric format or a hostname.
 *  @param port         A nul-terminated C string containing the port, which can be either in numeric or symbolic format.
 *                      If it is NULL, the listening port's number will be used.
 *
 *  @return             This function returns true if the address was added, false otherwise.
 */
bool meshlink_set_canonical_address(struct meshlink_handle *mesh, struct meshlink_node *node, const char *address, const char *port) __attribute__((__warn_unused_result__));

/// Clear the canonical Address for a node.
/** This function clears the canonical Address for a node.
 *
 *  \memberof meshlink_node
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a struct meshlink_node describing the node.
 *
 *  @return             This function returns true if the address was removed, false otherwise.
 */
bool meshlink_clear_canonical_address(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));

/** This function allows the local node to join an existing mesh using an invitation URL generated by another node.
 *  An invitation can only be used if the local node has never connected to other nodes before.
 *  After a successfully accepted invitation, the name of the local node may have changed.
 *
 *  This function may only be called on a mesh that has not been started yet and which is not already part of an existing mesh.
 *  It is not valid to call this function when the storage policy set to MESHLINK_STORAGE_DISABLED.
 *
 *  This function is blocking. It can take several seconds before it returns.
 *  There is no guarantee it will perform a successful join.
 *  Failures might be caused by temporary network outages, or by the invitation having expired.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param invitation   A nul-terminated C string containing the invitation URL.
 *                      After this function returns, the application is free to overwrite or free @a invitation.
 *
 *  @return             This function returns true if the local node joined the mesh it was invited to, false otherwise.
 */
bool meshlink_join(struct meshlink_handle *mesh, const char *invitation) __attribute__((__warn_unused_result__));

/// Export the local node's key and addresses.
/** This function generates a string that contains the local node's public key and one or more IP addresses.
 *  The application can pass it in some way to another node, which can then import it,
 *  granting the local node access to the other node's mesh.
 *  The exported data does not contain any secret keys, it is therefore safe to transmit this data unencrypted over public networks.
 *
 *  Note that to create a working connection between two nodes, both must call meshink_export() and both must meshlink_import() each other's data.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *
 *  @return             This function returns a nul-terminated C string that contains the exported key and addresses, or NULL in case of an error.
 *                      The application should call free() after it has finished using this string.
 */
char *meshlink_export(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));

/// Import another node's key and addresses.
/** This function accepts a string containing the exported public key and addresses of another node.
 *  By importing this data, the local node grants the other node access to its mesh.
 *  The application should make sure that the data it imports is really coming from the node it wants to import,
 *
 *  Note that to create a working connection between two nodes, both must call meshink_export() and both must meshlink_import() each other's data.
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param data         A nul-terminated C string containing the other node's exported key and addresses.
 *                      After this function returns, the application is free to overwrite or free @a data.
 *
 *  @return             This function returns true if the data was valid and the other node has been granted access to the mesh, false otherwise.
 */
bool meshlink_import(struct meshlink_handle *mesh, const char *data) __attribute__((__warn_unused_result__));

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
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param node         A pointer to a struct meshlink_node describing the node to be forgotten.
 *
 *  @return             This function returns true if all currently known data about the node has been forgotten, false otherwise.
 */
bool meshlink_forget_node(struct meshlink_handle *mesh, struct meshlink_node *node);

/// Hint that a hostname may be found at an address
/** This function indicates to meshlink that the given hostname is likely found
 *  at the given IP address and port.
 *
 *  \memberof meshlink_node
 *  @param mesh     A handle which represents an instance of MeshLink.
 *  @param node     A pointer to a struct meshlink_node describing the node to add the address hint for.
 *  @param addr     The IP address and port which should be tried for the
 *                  given hostname. The caller is free to overwrite or free
 *                  this memory once meshlink returns.
 */
void meshlink_hint_address(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);

/// Inform MeshLink that the local network configuration might have changed
/** This is intended to be used when there is no way for MeshLink to get notifications of local network changes.
 *  It forces MeshLink to scan all network interfaces for changes in up/down status and new/removed addresses,
 *  and will immediately check if all connections to other nodes are still alive.
 *
 *  \memberof meshlink_handle
 *  @param mesh    A handle which represents an instance of MeshLink.
 */
void meshlink_hint_network_change(struct meshlink_handle *mesh);

/// Performs key rotation for an encrypted storage
/** This rotates the (master) key for an encrypted storage and discards the old key
 *  if the call succeeded. This is an atomic call.
 *
 *  \memberof meshlink_handle
 *  @param mesh     A handle which represents an instance of MeshLink.
 *  @param key      A pointer to the new key used to encrypt storage.
 *  @param keylen   The length of the new key in bytes.
 *
 *  @return         This function returns true if the key rotation for the encrypted storage succeeds, false otherwise.
 */
bool meshlink_encrypted_key_rotate(struct meshlink_handle *mesh, const void *key, size_t keylen) __attribute__((__warn_unused_result__));

/// Set device class timeouts
/** This sets the ping interval and timeout for a given device class.
 *
 *  \memberof meshlink_handle
 *  @param mesh          A handle which represents an instance of MeshLink.
 *  @param devclass      The device class to update
 *  @param pinginterval  The interval between keepalive packets, in seconds. The default is 60.
 *  @param pingtimeout   The required time within which a peer should respond, in seconds. The default is 5.
 *                       The timeout must be smaller than the interval.
 */
void meshlink_set_dev_class_timeouts(struct meshlink_handle *mesh, dev_class_t devclass, int pinginterval, int pingtimeout);

/// Set device class fast retry period
/** This sets the fast retry period for a given device class.
 *  During this period after the last time the mesh becomes unreachable, connections are tried once a second.
 *
 *  \memberof meshlink_handle
 *  @param mesh               A handle which represents an instance of MeshLink.
 *  @param devclass           The device class to update
 *  @param fast_retry_period  The period during which fast connection retries are done. The default is 0.
 */
void meshlink_set_dev_class_fast_retry_period(struct meshlink_handle *mesh, dev_class_t devclass, int fast_retry_period);

/// Set device class maximum timeout
/** This sets the maximum timeout for outgoing connection retries for a given device class.
 *
 *  \memberof meshlink_handle
 *  @param mesh          A handle which represents an instance of MeshLink.
 *  @param devclass      The device class to update
 *  @param maxtimeout    The maximum timeout between reconnection attempts, in seconds. The default is 900.
 */
void meshlink_set_dev_class_maxtimeout(struct meshlink_handle *mesh, dev_class_t devclass, int maxtimeout);

/// Reset all connection timers
/** This resets all timers related to connections, causing pending outgoing connections to be retried immediately.
 * It also sends keepalive packets on all active connections immediately.
 *
 *  \memberof meshlink_handle
 *  @param mesh          A handle which represents an instance of MeshLink.
 */
void meshlink_reset_timers(struct meshlink_handle *mesh);

/// Set which order invitations are committed
/** This determines in which order configuration files are written to disk during an invitation.
 *  By default, the invitee saves the configuration to disk first, then the inviter.
 *  By calling this function with @a inviter_commits_first set to true, the order is reversed.
 *
 *  \memberof meshlink_handle
 *  @param mesh               A handle which represents an instance of MeshLink.
 *  @param inviter_commits_first  If true, then the node that invited a peer will commit data to disk first.
 */
void meshlink_set_inviter_commits_first(struct meshlink_handle *mesh, bool inviter_commits_first);

/// Set the scheduling granularity of the application
/** This should be set to the effective scheduling granularity for the application.
 *  This depends on the scheduling granularity of the operating system, the application's
 *  process priority and whether it is running as realtime or not.
 *  The default value is 10000 (10 milliseconds).
 *
 *  \memberof meshlink_handle
 *  @param mesh         A handle which represents an instance of MeshLink.
 *  @param granularity  The scheduling granularity of the application in microseconds.
 */
void meshlink_set_scheduling_granularity(struct meshlink_handle *mesh, long granularity);

/// Sets the storage policy used by MeshLink
/** This sets the policy MeshLink uses when it has new information about nodes.
 *  By default, all udpates will be stored to disk (unless an ephemeral instance has been opened).
 *  Setting the policy to MESHLINK_STORAGE_KEYS_ONLY, only updates that contain new keys for nodes
 *  are stored.
 *  By setting the policy to MESHLINK_STORAGE_DISABLED, no updates will be stored.
 *
 *  \memberof meshlink_handle
 *  @param mesh    A handle which represents an instance of MeshLink.
 *  @param policy  The storage policy to use.
 */
void meshlink_set_storage_policy(struct meshlink_handle *mesh, meshlink_storage_policy_t policy);

#ifdef __cplusplus
}
#endif

#endif
