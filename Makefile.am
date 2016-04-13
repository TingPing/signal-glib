bin_PROGRAMS = sigtest

sigtest_LDADD = $(GLIB_LIBS) $(NETTLE_LIBS) $(LIBM) $(libdir)/libsignal-protocol-c.a
sigtest_CFLAGS = $(GLIB_CFLAGS) $(NETTLE_CFLAGS)
sigtest_SOURCES = \
	src/signal-client.c \
	src/crypto-provider.c

noinst_HEADERS = \
	src/crypto-provider.h

