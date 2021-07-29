TESTS = \
	basic \
	encrypted \
	ephemeral \
	import-export \
	invite-join \
	sign-verify \
	storage-policy

dist_check_SCRIPTS = $(TESTS)

AM_CPPFLAGS = $(PTHREAD_CFLAGS) -I${top_srcdir}/src -iquote. -Wall
AM_LDFLAGS = $(PTHREAD_LIBS)

check_PROGRAMS = \
	basic \
	encrypted \
	ephemeral \
	import-export \
	invite-join \
	sign-verify \
	storage-policy

if INSTALL_TESTS
bin_PROGRAMS = $(check_PROGRAMS)
endif

default_SOURCES = \
	full.c full.h \
	utils.c utils.h

LDADD = $(top_builddir)/src/libmeshlink-tiny.la -ldl

basic_SOURCES = basic.c $(default_SOURCES)
encrypted_SOURCES = encrypted.c $(default_SOURCES)
ephemeral_SOURCES = ephemeral.c $(default_SOURCES)
get_all_nodes_SOURCES = get-all-nodes.c $(default_SOURCES)
import_export_SOURCES = import-export.c $(default_SOURCES)
invite_join_SOURCES = invite-join.c $(default_SOURCES)
sign_verify_SOURCES = sign-verify.c $(default_SOURCES)
storage_policy_SOURCES = storage-policy.c $(default_SOURCES)
