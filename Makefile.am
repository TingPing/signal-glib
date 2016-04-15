bin_PROGRAMS = sigtest

sigtest_LDADD = $(GLIB_LIBS) $(NETTLE_LIBS) $(LIBM) $(libdir)/libsignal-protocol-c.a
sigtest_CFLAGS = $(GLIB_CFLAGS) $(NETTLE_CFLAGS) -DG_LOG_DOMAIN=\"Signal\"
sigtest_SOURCES = \
	src/signal-client.c \
	src/crypto-provider.c \
	src/identity-key-store.c \
	src/key-utils.c \
	src/pre-key-store.c

noinst_HEADERS = \
	src/crypto-provider.h \
	src/identity-key-store.h \
	src/key-utils.h

