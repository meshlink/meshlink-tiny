#ifdef NDEBUG
#undef NDEBUG
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#include "meshlink-tiny.h"
#include "devtools.h"
#include "utils.h"

#include "full.h"

static struct sync_flag baz_reachable;
static struct sync_flag seven_reachable;
static struct sync_flag commits_first_flag;

static void status_cb(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable && !strcmp(node->name, "baz")) {
		set_sync_flag(&baz_reachable, true);
	}

	if(reachable && !strcmp(node->name, "seven")) {
		set_sync_flag(&seven_reachable, true);
	}
}

static void invitee_commits_first_cb(bool inviter_first) {
	// Check that eight has committed foo's host config file, but foo hasn't committed eight's
	assert(access("invite_join_conf.8/foo", F_OK) == 0);
	assert(access("invite_join_conf.1/current/hosts/eight", F_OK) == -1 && errno == ENOENT);
	set_sync_flag(&commits_first_flag, !inviter_first);
}

static void inviter_commits_first_cb(bool inviter_first) {
	// Check that foo has committed nine's host config file, but nine hasn't committed foo's
	assert(access("invite_join_conf.1/current/hosts/nine", F_OK) == 0);
	assert(access("invite_join_conf.9/foo", F_OK) == -1 && errno == ENOENT);
	set_sync_flag(&commits_first_flag, inviter_first);
}

int main(void) {
	init_full();

	init_sync_flag(&baz_reachable);
	init_sync_flag(&seven_reachable);
	init_sync_flag(&commits_first_flag);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	assert(full_meshlink_destroy("invite_join_conf.1"));
	assert(meshlink_destroy("invite_join_conf.2"));
	assert(meshlink_destroy("invite_join_conf.3"));
	assert(meshlink_destroy("invite_join_conf.4"));
	assert(meshlink_destroy("invite_join_conf.5"));
	assert(meshlink_destroy("invite_join_conf.6"));
	assert(meshlink_destroy("invite_join_conf.7"));
	assert(meshlink_destroy("invite_join_conf.8"));
	assert(meshlink_destroy("invite_join_conf.9"));

	// Open thee new meshlink instance.

	meshlink_handle_t *mesh1 = full_meshlink_open("invite_join_conf.1", "foo", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh1);

	meshlink_handle_t *mesh2 = meshlink_open("invite_join_conf.2", "bar", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh2);

	meshlink_handle_t *mesh3 = meshlink_open("invite_join_conf.3", "quux", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh3);

	// Have the first instance generate invitations.

	full_meshlink_set_node_status_cb(mesh1, status_cb);

	assert(full_meshlink_set_canonical_address(mesh1, full_meshlink_get_self(mesh1), "localhost", NULL));

	char *baz_url = full_meshlink_invite(mesh1, NULL, "baz");
	assert(baz_url);

	char *quux_url = full_meshlink_invite(mesh1, NULL, "quux");
	assert(quux_url);

	// Check that the second instances cannot join if it is already started

	assert(full_meshlink_start(mesh1));
	assert(meshlink_start(mesh2));
	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_join(mesh2, baz_url));
	assert(meshlink_errno = MESHLINK_EINVAL);

	// Have the second instance join the first.

	meshlink_stop(mesh2);
	assert(meshlink_join(mesh2, baz_url));
	assert(meshlink_start(mesh2));

	// Wait for the two to connect.

	assert(wait_sync_flag(&baz_reachable, 20));

	// Wait for UDP communication to become possible.

	int pmtu = full_meshlink_get_pmtu(mesh1, meshlink_get_node(mesh1, "baz"));

	for(int i = 0; i < 10 && !pmtu; i++) {
		sleep(1);
		pmtu = full_meshlink_get_pmtu(mesh1, meshlink_get_node(mesh1, "baz"));
	}

	assert(pmtu);

	// Check that an invitation cannot be used twice

	assert(!meshlink_join(mesh3, baz_url));
	free(baz_url);

	// Check that nodes cannot join with expired invitations

	full_meshlink_set_invitation_timeout(mesh1, 0);

	assert(!meshlink_join(mesh3, quux_url));
	free(quux_url);

	// Check that existing nodes cannot join another mesh

	char *corge_url = full_meshlink_invite(mesh1, NULL, "corge");
	assert(corge_url);

	meshlink_stop(mesh2);

	assert(!meshlink_join(mesh2, corge_url));
	free(corge_url);

	// Check that invitations work correctly after changing ports

	full_meshlink_set_invitation_timeout(mesh1, 86400);
	full_meshlink_stop(mesh1);
	meshlink_stop(mesh3);

	int oldport = full_meshlink_get_port(mesh1);
	bool success = false;

	for(int i = 0; !success && i < 100; i++) {
		success = full_meshlink_set_port(mesh1, 0x9000 + rand() % 0x1000);
	}

	assert(success);
	int newport = full_meshlink_get_port(mesh1);
	assert(oldport != newport);

	assert(full_meshlink_set_canonical_address(mesh1, meshlink_get_self(mesh1), "localhost", NULL));

	assert(full_meshlink_start(mesh1));
	quux_url = full_meshlink_invite(mesh1, NULL, "quux");
	assert(quux_url);

	// The old port should not be in the invitation URL

	char portstr[10];
	snprintf(portstr, sizeof(portstr), ":%d", oldport);
	assert(!strstr(quux_url, portstr));

	// The new port should be in the invitation URL

	snprintf(portstr, sizeof(portstr), ":%d", newport);
	assert(strstr(quux_url, portstr));

	// The invitation should work

	assert(meshlink_join(mesh3, quux_url));
	free(quux_url);

	// Check that adding duplicate addresses get removed correctly

	assert(full_meshlink_add_invitation_address(mesh1, "localhost", portstr + 1));
	corge_url = full_meshlink_invite(mesh1, NULL, "corge");
	assert(corge_url);
	char *localhost = strstr(corge_url, "localhost");
	assert(localhost);
	assert(!strstr(localhost + 1, "localhost"));
	free(corge_url);

	// Check that resetting and adding multiple, different invitation address works

	full_meshlink_clear_invitation_addresses(mesh1);
	assert(full_meshlink_add_invitation_address(mesh1, "1.invalid.", "12345"));
	assert(full_meshlink_add_invitation_address(mesh1, "2.invalid.", NULL));
	assert(full_meshlink_add_invitation_address(mesh1, "3.invalid.", NULL));
	assert(full_meshlink_add_invitation_address(mesh1, "4.invalid.", NULL));
	assert(full_meshlink_add_invitation_address(mesh1, "5.invalid.", NULL));
	char *grault_url = full_meshlink_invite(mesh1, NULL, "grault");
	assert(grault_url);
	localhost = strstr(grault_url, "localhost");
	assert(localhost);
	char *invalid1 = strstr(grault_url, "1.invalid.:12345");
	assert(invalid1);
	char *invalid5 = strstr(grault_url, "5.invalid.");
	assert(invalid5);

	// Check that explicitly added invitation addresses come before others, in the order they were specified.

	assert(invalid1 < invalid5);
	assert(invalid5 < localhost);
	free(grault_url);

	// Check inviting nodes into a submesh

	assert(!full_meshlink_get_node_submesh(mesh1, meshlink_get_self(mesh1)));

	meshlink_handle_t *mesh4 = meshlink_open("invite_join_conf.4", "four", "invite-join", DEV_CLASS_BACKBONE);
	meshlink_handle_t *mesh5 = meshlink_open("invite_join_conf.5", "five", "invite-join", DEV_CLASS_BACKBONE);
	meshlink_handle_t *mesh6 = meshlink_open("invite_join_conf.6", "six", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh4);
	assert(mesh5);
	assert(mesh6);

	meshlink_submesh_t *submesh1 = full_meshlink_submesh_open(mesh1, "submesh1");
	meshlink_submesh_t *submesh2 = full_meshlink_submesh_open(mesh1, "submesh2");
	assert(submesh1);
	assert(submesh2);

	char *four_url = full_meshlink_invite(mesh1, submesh1, mesh4->name);
	char *five_url = full_meshlink_invite(mesh1, submesh1, mesh5->name);
	char *six_url = full_meshlink_invite(mesh1, submesh2, mesh6->name);
	assert(four_url);
	assert(five_url);
	assert(six_url);

	assert(meshlink_join(mesh4, four_url));
	assert(meshlink_join(mesh5, five_url));
	assert(meshlink_join(mesh6, six_url));

	free(four_url);
	free(five_url);
	free(six_url);

	assert(meshlink_start(mesh2));
	assert(meshlink_start(mesh4));
	assert(meshlink_start(mesh5));
	assert(meshlink_start(mesh6));

	// Wait for nodes to connect, and check that foo sees the right submeshes

	sleep(2);
	meshlink_node_t *mesh1_four = full_meshlink_get_node(mesh1, mesh4->name);
	meshlink_node_t *mesh1_six = full_meshlink_get_node(mesh1, mesh6->name);
	assert(full_meshlink_get_node_submesh(mesh1, meshlink_get_self(mesh1)) == NULL);
	assert(full_meshlink_get_node_submesh(mesh1, mesh1_four) == submesh1);
	assert(full_meshlink_get_node_submesh(mesh1, mesh1_six) == submesh2);

	// Check that none of the tiny nodes can see each other, regardless of which submesh they are in

	assert(!meshlink_get_node(mesh2, mesh4->name));
	assert(!meshlink_get_node(mesh2, mesh5->name));
	assert(!meshlink_get_node(mesh2, mesh6->name));
	assert(!meshlink_get_node(mesh4, mesh2->name));
	assert(!meshlink_get_node(mesh5, mesh2->name));
	assert(!meshlink_get_node(mesh6, mesh2->name));

	assert(!meshlink_get_node(mesh4, mesh5->name));
	assert(!meshlink_get_node(mesh5, mesh4->name));


	assert(!meshlink_get_node(mesh4, mesh6->name));
	assert(!meshlink_get_node(mesh5, mesh6->name));
	assert(!meshlink_get_node(mesh6, mesh4->name));
	assert(!meshlink_get_node(mesh6, mesh5->name));

	// Test case #2: check invalid parameters

	meshlink_handle_t *mesh7 = meshlink_open("invite_join_conf.7", "seven", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh7);
	char *seven_url = full_meshlink_invite(mesh1, NULL, "seven");
	assert(seven_url);

	meshlink_errno = MESHLINK_OK;
	assert(!full_meshlink_invite(NULL, NULL, "seven"));
	assert(*full_meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!full_meshlink_invite(mesh1, NULL, NULL));
	assert(*full_meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!full_meshlink_invite(mesh1, NULL, ""));
	assert(*full_meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_join(NULL, seven_url));
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_join(mesh7, NULL));
	assert(meshlink_errno == MESHLINK_EINVAL);

	meshlink_errno = MESHLINK_OK;
	assert(!meshlink_join(mesh7, ""));
	assert(meshlink_errno == MESHLINK_EINVAL);

	// Test case #3 and #4: check persistence of inviter and invitee

	assert(meshlink_join(mesh7, seven_url));
	free(seven_url);
	full_meshlink_close(mesh1);
	meshlink_stop(mesh2);
	meshlink_stop(mesh3);
	meshlink_stop(mesh4);
	meshlink_stop(mesh5);
	meshlink_stop(mesh6);
	meshlink_close(mesh7);
	mesh1 = full_meshlink_open("invite_join_conf.1", "foo", "invite-join", DEV_CLASS_BACKBONE);
	mesh7 = meshlink_open("invite_join_conf.7", "seven", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh1);
	assert(mesh7);
	full_meshlink_enable_discovery(mesh1, false);
	full_meshlink_set_node_status_cb(mesh1, status_cb);
	assert(full_meshlink_start(mesh1));
	assert(meshlink_start(mesh7));
	assert(wait_sync_flag(&seven_reachable, 5));
	meshlink_stop(mesh7);

	// Test case #6 and #7: check invalid inviter_commits_first combinations

	meshlink_handle_t *mesh8 = meshlink_open("invite_join_conf.8", "eight", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh8);
	char *eight_url = full_meshlink_invite(mesh1, NULL, "eight");
	assert(eight_url);
	full_meshlink_set_inviter_commits_first(mesh1, true);
	meshlink_set_inviter_commits_first(mesh8, false);
	assert(!meshlink_join(mesh8, eight_url));
	free(eight_url);

	eight_url = full_meshlink_invite(mesh1, NULL, "eight");
	full_meshlink_set_inviter_commits_first(mesh1, false);
	meshlink_set_inviter_commits_first(mesh8, true);
	assert(!meshlink_join(mesh8, eight_url));
	free(eight_url);

	// Test case #5: test invitee committing first scenario

	eight_url = full_meshlink_invite(mesh1, NULL, "eight");
	full_meshlink_set_inviter_commits_first(mesh1, false);
	meshlink_set_inviter_commits_first(mesh8, false);
	devtool_set_inviter_commits_first = invitee_commits_first_cb;
	assert(meshlink_join(mesh8, eight_url));
	free(eight_url);
	assert(wait_sync_flag(&commits_first_flag, 5));

	// Test case #6: test inviter committing first scenario

	meshlink_handle_t *mesh9 = meshlink_open("invite_join_conf.9", "nine", "invite-join", DEV_CLASS_BACKBONE);
	assert(mesh9);
	char *nine_url = full_meshlink_invite(mesh1, NULL, "nine");
	full_meshlink_set_inviter_commits_first(mesh1, true);
	meshlink_set_inviter_commits_first(mesh9, true);
	*full_devtool_set_inviter_commits_first = inviter_commits_first_cb;
	reset_sync_flag(&commits_first_flag);
	assert(meshlink_join(mesh9, nine_url));
	free(nine_url);
	assert(wait_sync_flag(&commits_first_flag, 5));

	// Clean up.

	meshlink_close(mesh9);
	meshlink_close(mesh8);
	meshlink_close(mesh7);
	meshlink_close(mesh6);
	meshlink_close(mesh5);
	meshlink_close(mesh4);
	meshlink_close(mesh3);
	meshlink_close(mesh2);
	full_meshlink_close(mesh1);
}
