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
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src \
	-I$(top_srcdir)/src/storage

libsignal_glib_la_SOURCES = \
	src/signal-main.c \
	src/signal-identity.c \
	src/signal-storage.c \
	src/signal-storage-keyfile.c \
	src/crypto-provider.c \
	src/storage/identity-key-store.c \
	src/storage/key-utils.c \
	src/storage/pre-key-store.c \
	src/storage/sender-key-store.c \
	src/storage/session-store.c \
	src/storage/signed-pre-key-store.c

libsignal_glib_la_LDFLAGS = \
	-avoid-version
#	-export-symbols-regex '^signal_.+'

pkginclude_HEADERS = \
	src/signal-glib.h \
	src/signal-identity.h \
	src/signal-storage.h \
	src/signal-storage-keyfile.h

noinst_HEADERS = \
	src/crypto-provider.h \
	src/storage/identity-key-store.h \
	src/storage/key-utils.h \
	src/storage/pre-key-store.h \
	src/storage/sender-key-store.h \
	src/storage/session-store.h \
	src/signal-glib-private.h \
	src/storage/signed-pre-key-store.h

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
	MALLOC_PERTURB_=$$(($${RANDOM:-256} % 256))

test_libs = \
	$(GLIB_LIBS) \
	libsignal-glib.la

test_cflags = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src

TESTS = tests/test-client
tests_test_client_CFLAGS = $(test_cflags)
tests_test_client_LDADD = $(test_libs)

TESTS += tests/test-axolotl-client
tests_test_axolotl_client_LDADD = $(test_libs)
tests_test_axolotl_client_CFLAGS = \
	$(test_cflags) \
	-I$(top_srcdir)/src/storage \
	-I$(top_srcdir)/contrib/libsignal-protocol-c/src

check_PROGRAMS = $(TESTS)

EXTRA_DIST = tools
