AC_INIT([Degreaser], [0.1])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([foreign -Wall no-define])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CXX

AX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS -I/usr/local/include"
LDFLAGS="-L/usr/local/lib"
	
AC_LANG(C++)

AX_WITH_CURSES

AX_CRAFTER
LIBCAP_NG_PATH

AC_SUBST(CRAFTER_CXXFLAGS)
AC_SUBST(CRAFTER_LIBS)

AC_CHECK_HEADER([cperm.h],
	AC_CHECK_LIB([cperm], [cperm_create], ,
		AC_MSG_WARN([Can not link against libcperm. Random scanning will not be available.])),
	AC_MSG_WARN([Can not find cperm.h. Random scanning will not be available.]))

AC_OUTPUT([Makefile])

echo
echo "Degreaser configuration complete."
echo
echo "Optional Library Support:"
if test "$CAPNG_LDADD" = ""; then
	echo "    libcap-ng:  no (recommend installing libcap-ng-dev)"
else
	echo "    libcap-ng:  yes"
fi
if [[[ "$LIBS" =~ ".*-lperm.*" ]]]; then
	echo "    libcperm:    no (recommend installing libcperm)"
else
	echo "    libcperm:    yes"
fi
if test "$CURSES_LIB" = ""; then
	echo "    libcurses:  no (recommend installing libncurses-dev)"
else
	echo "    libcurses:  yes"
fi
echo
echo "Run 'make && make install' to install degreaser."
echo
