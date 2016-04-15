AC_PREREQ([2.69])
AC_INIT([signal-glib], [0.0.0])
AC_CONFIG_SRCDIR([src/signal-main.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile])

AX_IS_RELEASE([git-directory])
AX_CHECK_ENABLE_DEBUG([yes], [G_ENABLE_DEBUG],
                      [G_DISABLE_ASSERT G_DISABLE_CHECKS G_DISABLE_CAST_CHECKS])

AC_PROG_CC
AC_PROG_CC_C99

AM_INIT_AUTOMAKE([1.11.1 dist-xz no-dist-gzip subdir-objects no-define foreign])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT
LT_LIB_M

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([GLIB], [gio-2.0])
PKG_CHECK_MODULES([NETTLE], [nettle])

AX_APPEND_COMPILE_FLAGS([ \
	-std=gnu99 \
	-funsigned-char \
	-fstack-protector-strong \
	-fPIE \
	-fPIC \
	-Wall \
	-Wextra \
	-Wconversion \
	-Winline \
	-Wno-padded \
	-Wno-unused-parameter \
	-Wmissing-prototypes \
	-Werror=implicit-function-declaration \
	-Werror=pointer-arith \
	-Werror=init-self \
	-Werror=format-security \
	-Werror=format=2 \
	-Werror=missing-include-dirs \
	-Werror=date-time \
])

AX_APPEND_LINK_FLAGS([ \
	-pie \
	-Wl,-z,relro \
	-Wl,-z,now \
])

AC_OUTPUT
echo "

	$PACKAGE $VERSION

	prefix ....... : $prefix
"
