# --------------- libsignal-glib ---------------

lib_LTLIBRARIES = libsignal-glib.la

libsignal_glib_la_LIBADD = \
	$(GLIB_LIBS) \
	$(NETTLE_LIBS) \
	$(LIBM) \
	libsignal-protocol-c.la

libsignal_glib_la_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(NETTLE_CFLAGS) \
	-DG_LOG_DOMAIN=\"Signal\" \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src

libsignal_glib_la_SOURCES = \
	src/signal-main.c \
	src/crypto-provider.c \
	src/identity-key-store.c \
	src/key-utils.c \
	src/pre-key-store.c \
	src/sender-key-store.c \
	src/session-store.c \
	src/signed-pre-key-store.c

libsignal_glib_la_LDFLAGS = \
	-export-symbols-regex '^signal_.+' \
	-avoid-version

pkginclude_HEADERS = \
	src/signal-glib.h

noinst_HEADERS = \
	src/crypto-provider.h \
	src/identity-key-store.h \
	src/key-utils.h \
	src/pre-key-store.h \
	src/sender-key-store.h \
	src/session-store.h \
	src/signal-glib-private.h \
	src/signed-pre-key-store.h

# ---------------- libsignal-protocol-c ----------------

noinst_LTLIBRARIES = libsignal-protocol-c.la

libsignal_protocol_c_la_CFLAGS = \
	-w \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src/curve25519/ed25519 \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src/curve25519/ed25519/additions \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src/curve25519/ed25519/nacl_includes

include Makefile.sources

# --------------- tests ------------------

LOG_COMPILER = tools/tap-test

TESTS_ENVIRONMENT = \
	GOBJECT_DEBUG=instance-count \
	G_TEST_SRCDIR="$(abs_srcdir)" \
	G_TEST_BUILDDIR="$(abs_builddir)" \
	G_DEBUG=gc-friendly \
	MALLOC_CHECK_=2 \
	MALLOC_PERTURB_=$$(($${RANDOM:-256} % 256)) \
	G_MESSAGES_DEBUG=all

test_libs = \
	$(GLIB_LIBS) \
	libsignal-glib.la

test_cflags = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src

TESTS = tests/test-client
tests_test_client_CFLAGS = $(test_cflags)
tests_test_client_LDADD = $(test_libs)

check_PROGRAMS = $(TESTS)

EXTRA_DIST = tools
