#ifndef FULL_H
#define FULL_H

#include "meshlink-tiny.h"

typedef struct meshlink_channel meshlink_channel_t;
typedef struct meshlink_submesh meshlink_submesh_t;

struct meshlink_channel {
	struct meshlink_node *const node; ///< Pointer to the peer of this channel.
	void *priv;                       ///< Private pointer which may be set freely by the application, and is never used or modified by MeshLink.
};

struct meshlink_submesh {
	const char *const name; ///< Textual name of this Sub-Mesh. It is stored in a nul-terminated C string, which is allocated by MeshLink.
	void *priv;             ///< Private pointer which may be set freely by the application, and is never used or modified by MeshLink.
};

typedef void (*meshlink_node_pmtu_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *node, uint16_t pmtu);
typedef void (*meshlink_blacklisted_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *node);
typedef bool (*meshlink_channel_listen_cb_t)(struct meshlink_handle *mesh, struct meshlink_node *node, uint16_t port);
typedef bool (*meshlink_channel_accept_cb_t)(struct meshlink_handle *mesh, struct meshlink_channel *channel, uint16_t port, const void *data, size_t len);
typedef void (*meshlink_channel_receive_cb_t)(struct meshlink_handle *mesh, struct meshlink_channel *channel, const void *data, size_t len);
typedef void (*meshlink_channel_poll_cb_t)(struct meshlink_handle *mesh, struct meshlink_channel *channel, size_t len);
typedef void (*meshlink_aio_cb_t)(struct meshlink_handle *mesh, struct meshlink_channel *channel, const void *data, size_t len, void *priv);
typedef void (*meshlink_aio_fd_cb_t)(struct meshlink_handle *mesh, struct meshlink_channel *channel, int fd, size_t len, void *priv);

extern meshlink_errno_t *full_meshlink_errno;
extern const char *(*full_meshlink_strerror)(meshlink_errno_t err) __attribute__((__warn_unused_result__));
extern meshlink_open_params_t *(*full_meshlink_open_params_init)(const char *confbase, const char *name, const char *appname, dev_class_t devclass) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_open_params_free)(meshlink_open_params_t *params);
extern bool (*full_meshlink_open_params_set_netns)(meshlink_open_params_t *params, int netns) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_open_params_set_storage_key)(meshlink_open_params_t *params, const void *key, size_t keylen) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_open_params_set_storage_policy)(meshlink_open_params_t *params, meshlink_storage_policy_t policy) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_open_params_set_lock_filename)(meshlink_open_params_t *params, const char *filename) __attribute__((__warn_unused_result__));
extern struct meshlink_handle *(*full_meshlink_open_ex)(const meshlink_open_params_t *params) __attribute__((__warn_unused_result__));
extern struct meshlink_handle *(*full_meshlink_open)(const char *confbase, const char *name, const char *appname, dev_class_t devclass) __attribute__((__warn_unused_result__));
extern struct meshlink_handle *(*full_meshlink_open_encrypted)(const char *confbase, const char *name, const char *appname, dev_class_t devclass, const void *key, size_t keylen) __attribute__((__warn_unused_result__));
extern struct meshlink_handle *(*full_meshlink_open_ephemeral)(const char *name, const char *appname, dev_class_t devclass) __attribute__((__warn_unused_result__));
extern struct meshlink_submesh *(*full_meshlink_submesh_open)(struct meshlink_handle *mesh, const char *submesh) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_start)(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_stop)(struct meshlink_handle *mesh);
extern void (*full_meshlink_close)(struct meshlink_handle *mesh);
extern bool (*full_meshlink_destroy)(const char *confbase) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_destroy_ex)(const meshlink_open_params_t *params) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_set_receive_cb)(struct meshlink_handle *mesh, meshlink_receive_cb_t cb);
extern void (*full_meshlink_set_connection_try_cb)(struct meshlink_handle *mesh, meshlink_connection_try_cb_t cb);
extern void (*full_meshlink_set_node_status_cb)(struct meshlink_handle *mesh, meshlink_node_status_cb_t cb);
extern void (*full_meshlink_set_node_pmtu_cb)(struct meshlink_handle *mesh, meshlink_node_pmtu_cb_t cb);
extern void (*full_meshlink_set_node_duplicate_cb)(struct meshlink_handle *mesh, meshlink_node_duplicate_cb_t cb);
extern void (*full_meshlink_set_log_cb)(struct meshlink_handle *mesh, meshlink_log_level_t level, meshlink_log_cb_t cb);
extern void (*full_meshlink_set_error_cb)(struct meshlink_handle *mesh, meshlink_error_cb_t cb);
extern void (*full_meshlink_set_blacklisted_cb)(struct meshlink_handle *mesh, meshlink_blacklisted_cb_t cb);
extern bool (*full_meshlink_send)(struct meshlink_handle *mesh, struct meshlink_node *destination, const void *data, size_t len) __attribute__((__warn_unused_result__));
extern ssize_t (*full_meshlink_get_pmtu)(struct meshlink_handle *mesh, struct meshlink_node *destination) __attribute__((__warn_unused_result__));
extern struct meshlink_node *(*full_meshlink_get_self)(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));
extern struct meshlink_node *(*full_meshlink_get_node)(struct meshlink_handle *mesh, const char *name) __attribute__((__warn_unused_result__));
extern struct meshlink_submesh *(*full_meshlink_get_submesh)(struct meshlink_handle *mesh, const char *name) __attribute__((__warn_unused_result__));
extern char *(*full_meshlink_get_fingerprint)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern struct meshlink_node **(*full_meshlink_get_all_nodes)(struct meshlink_handle *mesh, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_sign)(struct meshlink_handle *mesh, const void *data, size_t len, void *signature, size_t *siglen) __attribute__((__warn_unused_result__));
extern struct meshlink_node **(*full_meshlink_get_all_nodes_by_dev_class)(struct meshlink_handle *mesh, dev_class_t devclass, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));
extern struct meshlink_node **(*full_meshlink_get_all_nodes_by_submesh)(struct meshlink_handle *mesh, struct meshlink_submesh *submesh, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));
extern struct meshlink_node **(*full_meshlink_get_all_nodes_by_last_reachable)(struct meshlink_handle *mesh, time_t start, time_t end, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));
extern struct meshlink_node **(*full_meshlink_get_all_nodes_by_blacklisted)(struct meshlink_handle *mesh, bool blacklisted, struct meshlink_node **nodes, size_t *nmemb) __attribute__((__warn_unused_result__));
extern dev_class_t (*full_meshlink_get_node_dev_class)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_get_node_blacklisted)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern struct meshlink_submesh *(*full_meshlink_get_node_submesh)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_get_node_reachability)(struct meshlink_handle *mesh, struct meshlink_node *node, time_t *last_reachable, time_t *last_unreachable);
extern bool (*full_meshlink_verify)(struct meshlink_handle *mesh, struct meshlink_node *source, const void *data, size_t len, const void *signature, size_t siglen) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_set_canonical_address)(struct meshlink_handle *mesh, struct meshlink_node *node, const char *address, const char *port) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_clear_canonical_address)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_add_invitation_address)(struct meshlink_handle *mesh, const char *address, const char *port) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_clear_invitation_addresses)(struct meshlink_handle *mesh);
extern char *(*full_meshlink_get_external_address)(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));
extern char *(*full_meshlink_get_external_address_for_family)(struct meshlink_handle *mesh, int address_family) __attribute__((__warn_unused_result__));
extern char *(*full_meshlink_get_local_address_for_family)(struct meshlink_handle *mesh, int address_family) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_add_external_address)(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));
extern int (*full_meshlink_get_port)(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_set_port)(struct meshlink_handle *mesh, int port) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_set_invitation_timeout)(struct meshlink_handle *mesh, int timeout);
extern char *(*full_meshlink_invite_ex)(struct meshlink_handle *mesh, struct meshlink_submesh *submesh, const char *name, uint32_t flags) __attribute__((__warn_unused_result__));
extern char *(*full_meshlink_invite)(struct meshlink_handle *mesh, struct meshlink_submesh *submesh, const char *name) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_join)(struct meshlink_handle *mesh, const char *invitation) __attribute__((__warn_unused_result__));
extern char *(*full_meshlink_export)(struct meshlink_handle *mesh) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_import)(struct meshlink_handle *mesh, const char *data) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_forget_node)(struct meshlink_handle *mesh, struct meshlink_node *node);
extern bool (*full_meshlink_blacklist)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_blacklist_by_name)(struct meshlink_handle *mesh, const char *name) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_whitelist)(struct meshlink_handle *mesh, struct meshlink_node *node) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_whitelist_by_name)(struct meshlink_handle *mesh, const char *name) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_set_default_blacklist)(struct meshlink_handle *mesh, bool blacklist);
extern void (*full_meshlink_set_channel_listen_cb)(struct meshlink_handle *mesh, meshlink_channel_listen_cb_t cb);
extern void (*full_meshlink_set_channel_accept_cb)(struct meshlink_handle *mesh, meshlink_channel_accept_cb_t cb);
extern void (*full_meshlink_set_channel_receive_cb)(struct meshlink_handle *mesh, struct meshlink_channel *channel, meshlink_channel_receive_cb_t cb);
extern void (*full_meshlink_set_channel_poll_cb)(struct meshlink_handle *mesh, struct meshlink_channel *channel, meshlink_channel_poll_cb_t cb);
extern void (*full_meshlink_set_channel_sndbuf)(struct meshlink_handle *mesh, struct meshlink_channel *channel, size_t size);
extern void (*full_meshlink_set_channel_rcvbuf)(struct meshlink_handle *mesh, struct meshlink_channel *channel, size_t size);
extern void (*full_meshlink_set_channel_sndbuf_storage)(struct meshlink_handle *mesh, struct meshlink_channel *channel, void *buf, size_t size);
extern void (*full_meshlink_set_channel_rcvbuf_storage)(struct meshlink_handle *mesh, struct meshlink_channel *channel, void *buf, size_t size);
extern void (*full_meshlink_set_channel_flags)(struct meshlink_handle *mesh, struct meshlink_channel *channel, uint32_t flags);
extern struct meshlink_channel *(*full_meshlink_channel_open_ex)(struct meshlink_handle *mesh, struct meshlink_node *node, uint16_t port, meshlink_channel_receive_cb_t cb, const void *data, size_t len, uint32_t flags) __attribute__((__warn_unused_result__));
extern struct meshlink_channel *(*full_meshlink_channel_open)(struct meshlink_handle *mesh, struct meshlink_node *node, uint16_t port, meshlink_channel_receive_cb_t cb, const void *data, size_t len) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_channel_shutdown)(struct meshlink_handle *mesh, struct meshlink_channel *channel, int direction);
extern void (*full_meshlink_channel_close)(struct meshlink_handle *mesh, struct meshlink_channel *channel);
extern void (*full_meshlink_channel_abort)(struct meshlink_handle *mesh, struct meshlink_channel *channel);
extern ssize_t (*full_meshlink_channel_send)(struct meshlink_handle *mesh, struct meshlink_channel *channel, const void *data, size_t len) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_channel_aio_send)(struct meshlink_handle *mesh, struct meshlink_channel *channel, const void *data, size_t len, meshlink_aio_cb_t cb, void *priv) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_channel_aio_fd_send)(struct meshlink_handle *mesh, struct meshlink_channel *channel, int fd, size_t len, meshlink_aio_fd_cb_t cb, void *priv) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_channel_aio_receive)(struct meshlink_handle *mesh, struct meshlink_channel *channel, const void *data, size_t len, meshlink_aio_cb_t cb, void *priv) __attribute__((__warn_unused_result__));
extern bool (*full_meshlink_channel_aio_fd_receive)(struct meshlink_handle *mesh, struct meshlink_channel *channel, int fd, size_t len, meshlink_aio_fd_cb_t cb, void *priv) __attribute__((__warn_unused_result__));
extern uint32_t (*full_meshlink_channel_get_flags)(struct meshlink_handle *mesh, struct meshlink_channel *channel) __attribute__((__warn_unused_result__));
extern size_t (*full_meshlink_channel_get_sendq)(struct meshlink_handle *mesh, struct meshlink_channel *channel) __attribute__((__warn_unused_result__));
extern size_t (*full_meshlink_channel_get_recvq)(struct meshlink_handle *mesh, struct meshlink_channel *channel) __attribute__((__warn_unused_result__));
extern size_t (*full_meshlink_channel_get_mss)(struct meshlink_handle *mesh, struct meshlink_channel *channel) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_set_node_channel_timeout)(struct meshlink_handle *mesh, struct meshlink_node *node, int timeout);
extern void (*full_meshlink_hint_address)(struct meshlink_handle *mesh, struct meshlink_node *node, const struct sockaddr *addr);
extern void (*full_meshlink_enable_discovery)(struct meshlink_handle *mesh, bool enable);
extern void (*full_meshlink_hint_network_change)(struct meshlink_handle *mesh);
extern bool (*full_meshlink_encrypted_key_rotate)(struct meshlink_handle *mesh, const void *key, size_t keylen) __attribute__((__warn_unused_result__));
extern void (*full_meshlink_set_dev_class_timeouts)(struct meshlink_handle *mesh, dev_class_t devclass, int pinginterval, int pingtimeout);
extern void (*full_meshlink_set_dev_class_fast_retry_period)(struct meshlink_handle *mesh, dev_class_t devclass, int fast_retry_period);
extern void (*full_meshlink_set_dev_class_maxtimeout)(struct meshlink_handle *mesh, dev_class_t devclass, int maxtimeout);
extern void (*full_meshlink_reset_timers)(struct meshlink_handle *mesh);
extern void (*full_meshlink_set_inviter_commits_first)(struct meshlink_handle *mesh, bool inviter_commits_first);
extern void (*full_meshlink_set_external_address_discovery_url)(struct meshlink_handle *mesh, const char *url);
extern void (*full_meshlink_set_scheduling_granularity)(struct meshlink_handle *mesh, long granularity);
extern void (*full_meshlink_set_storage_policy)(struct meshlink_handle *mesh, meshlink_storage_policy_t policy);

typedef void (*full_devtool_set_inviter_commits_first_t)(bool inviter_commited_first);
extern full_devtool_set_inviter_commits_first_t *full_devtool_set_inviter_commits_first;

void init_full(void);
#endif
