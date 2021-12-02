#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include "../src/meshlink-tiny.h"

static void log_message(meshlink_handle_t *mesh, meshlink_log_level_t level, const char *text) {
	(void)mesh;

	static const char *levelstr[] = {
		[MESHLINK_DEBUG] = "\x1b[34mDEBUG",
		[MESHLINK_INFO] = "\x1b[32mINFO",
		[MESHLINK_WARNING] = "\x1b[33mWARNING",
		[MESHLINK_ERROR] = "\x1b[31mERROR",
		[MESHLINK_CRITICAL] = "\x1b[31mCRITICAL",
	};

	fprintf(stderr, "%s:\x1b[0m %s\n", levelstr[level], text);
}

static void receive(meshlink_handle_t *mesh, meshlink_node_t *source, const void *data, size_t len) {
	(void)mesh;

	const char *msg = data;

	if(!len || msg[len - 1]) {
		fprintf(stderr, "Received invalid data from %s\n", source->name);
		return;
	}

	printf("%s says: %s\n", source->name, msg);
}

static void node_status(meshlink_handle_t *mesh, meshlink_node_t *node, bool reachable) {
	(void)mesh;

	if(reachable) {
		printf("%s joined.\n", node->name);
	} else {
		printf("%s left.\n", node->name);
	}
}

static void parse_command(meshlink_handle_t *mesh, char *buf) {
	char *arg = strchr(buf, ' ');

	if(arg) {
		*arg++ = 0;
	}

	if(!strcasecmp(buf, "join")) {
		if(!arg) {
			fprintf(stderr, "/join requires an argument!\n");
			return;
		}

		meshlink_stop(mesh);

		if(!meshlink_join(mesh, arg)) {
			fprintf(stderr, "Could not join using invitation: %s\n", meshlink_strerror(meshlink_errno));
		} else {
			fprintf(stderr, "Invitation accepted!\n");
		}

		if(!meshlink_start(mesh)) {
			fprintf(stderr, "Could not restart MeshLink: %s\n", meshlink_strerror(meshlink_errno));
			exit(1);
		}
	} else if(!strcasecmp(buf, "quit")) {
		printf("Bye!\n");
		fclose(stdin);
	} else if(!strcasecmp(buf, "help")) {
		printf(
		        "<name>: <message>     Send a message to the given node.\n"
		        "                      Subsequent messages don't need the <name>: prefix.\n"
		        "/join <invitation>    Join an existing mesh using an invitation.\n"
		        "/kick <name>          Blacklist the given node.\n"
		        "/who [<name>]         List all nodes or show information about the given node.\n"
		        "/quit                 Exit this program.\n"
		);
	} else {
		fprintf(stderr, "Unknown command '/%s'\n", buf);
	}
}

static void parse_input(meshlink_handle_t *mesh, char *buf) {
	static meshlink_node_t *destination;
	size_t len;

	if(!buf) {
		return;
	}

	// Remove newline.

	len = strlen(buf);

	if(len && buf[len - 1] == '\n') {
		buf[--len] = 0;
	}

	if(len && buf[len - 1] == '\r') {
		buf[--len] = 0;
	}

	// Ignore empty lines.

	if(!len) {
		return;
	}

	// Commands start with '/'

	if(*buf == '/') {
		parse_command(mesh, buf + 1);
		return;
	}

	// Lines in the form "name: message..." set the destination node.

	char *msg = buf;
	char *colon = strchr(buf, ':');

	if(colon) {
		*colon = 0;
		msg = colon + 1;

		if(*msg == ' ') {
			msg++;
		}

		destination = meshlink_get_node(mesh, buf);

		if(!destination) {
			fprintf(stderr, "Error looking up '%s': %s\n", buf, meshlink_strerror(meshlink_errno));
			return;
		}
	}

	if(!destination) {
		fprintf(stderr, "Who are you talking to? Write 'name: message...'\n");
		return;
	}

	if(!meshlink_send(mesh, destination, msg, strlen(msg) + 1)) {
		fprintf(stderr, "Could not send message to '%s': %s\n", destination->name, meshlink_strerror(meshlink_errno));
		return;
	}

	printf("Message sent to '%s'.\n", destination->name);
}

static char *flatten(const char *filename) {
	char *result = strdup(filename);
	assert(result);

	for(char *c = result; *c; c++) {
		if(*c == '/') {
			*c = ':';
		}
	}

	return result;
}

static bool load_cb(meshlink_handle_t *mesh, const char *key, void *data, size_t *len) {
	fprintf(stderr, "load_cb(%s, %s, %p, %zu)\n", mesh->name, key, data, *len);
	FILE *f = fopen(flatten(key), "r");
	assert(f);
	fread(data, 1, *len, f);
	fseek(f, 0, SEEK_END);
	*len = ftell(f);
	assert(!fclose(f));
	return true;
}

static bool store_cb(meshlink_handle_t *mesh, const char *key, const void *data, size_t len) {
	fprintf(stderr, "store_cb(%s, %s, %p, %zu)\n", mesh->name, key, data, len);
	FILE *f = fopen(flatten(key), "w");
	assert(f);
	assert(fwrite(data, len, 1, f) == 1);
	assert(!fclose(f));
	return true;
}

static bool ls_cb(meshlink_handle_t *mesh, meshlink_ls_entry_cb_t entry_cb) {
	fprintf(stderr, "ls_cb()");
	DIR *dir = opendir(".");
	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(ent->d_name[0] != '.') {
			entry_cb(mesh, ent->d_name, 0);
		}
	}

	closedir(dir);

	return true;
}

int main(int argc, char *argv[]) {
	const char *confbase = ".chat";
	const char *nick = NULL;
	char buf[1024];

	if(argc > 1) {
		confbase = argv[1];
	}

	if(argc > 2) {
		nick = argv[2];
	}

	assert(mkdir(confbase, 0700) == 0);
	assert(chdir(confbase) == 0);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_message);
	meshlink_open_params_t *params = meshlink_open_params_init(confbase, nick, "chat", DEV_CLASS_STATIONARY);
	//assert(meshlink_open_params_set_storage_key(params, "12345", 5));
	assert(meshlink_open_params_set_storage_callbacks(params, load_cb, store_cb, ls_cb));
	meshlink_handle_t *mesh = meshlink_open_ex(params);
	meshlink_open_params_free(params);

	if(!mesh) {
		fprintf(stderr, "Could not open MeshLink: %s\n", meshlink_strerror(meshlink_errno));
		return 1;
	}

	meshlink_set_receive_cb(mesh, receive);
	meshlink_set_node_status_cb(mesh, node_status);
	meshlink_set_log_cb(mesh, MESHLINK_INFO, log_message);

	if(!meshlink_start(mesh)) {
		fprintf(stderr, "Could not start MeshLink: %s\n", meshlink_strerror(meshlink_errno));
		return 1;
	}

	printf("Chat started.\nType /help for a list of commands.\n");

	while(fgets(buf, sizeof(buf), stdin)) {
		parse_input(mesh, buf);
	}

	printf("Chat stopping.\n");

	meshlink_stop(mesh);
	meshlink_close(mesh);

	return 0;
}
