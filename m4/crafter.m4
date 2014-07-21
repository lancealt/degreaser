
AC_DEFUN([AX_CRAFTER], [
		CRAFTER_CXXFLAGS=""
		CRAFTER_LDFLAGS=""
		CRAFTER_LIBS="-lcrafter -lpcap -lresolv"

		AC_ARG_ENABLE([static-crafter],
			AS_HELP_STRING(
				[--enable-static-crafter=@<:@ARG@:>@],
				[statically link libcrafter @<:@default=no@:>@]
			),
			[
			if test "$withval" = "yes"; then
				STATIC_CRAFTER="yes"
			else
				STATIC_CRAFTER="no"
			fi
			],
			[STATIC_CRAFTER="no"]
		)


		AC_CHECK_HEADERS([crafter.h], [], [
			AC_MSG_FAILURE([could not find crafter.h])
			])


		if test "x$STATIC_CRAFTER" = "xyes"; then
			dnl
			dnl User requested linking against static libcrafter
			dnl   NOTE: static libcrafter requires libpcap and libresolv
			dnl
			saved_LIBS=$LIBS
			CRAFTER_LIBS="-Wl,-Bstatic -Wl,-lcrafter -Wl,-Bdynamic -lpcap -lresolv"
			LIBS="$LIBS $CRAFTER_LIBS"
			AC_MSG_CHECKING([for libcrafter])
			AC_LINK_IFELSE([
					AC_LANG_PROGRAM(
						[#include<crafter.h>],
						[Crafter::RawLayer hello("hello");]
					)],
					[
					CRAFTER_MODE="static (local)"
					CRAFTER_LIBS="-Wl,-Bstatic -Wl,-lcrafter -Wl,-Bdynamic -Wc,-lpcap -Wc,-lresolv"
					AC_MSG_RESULT([yes])
					],
					[
					CRAFTER_LIBS="$srcdir/static_libs/lib64/libcrafter.a -Wc,-lpcap -Wc,-lresolv"
					LIBS="$saved_LIBS $CRAFTER_LIBS"
					AC_LINK_IFELSE([
							AC_LANG_PROGRAM(
								[#include<crafter.h>],
								[Crafter::RawLayer hello("hello");]
							)],
							[
							CRAFTER_MODE="static (dist)"
							AC_MSG_RESULT([yes])
							],
							[
							AC_MSG_RESULT([no])
							AC_MSG_FAILURE([could not find or link against static libcrafter.])
							]
					)
					]
			)
			LIBS=$saved_LIBS
		else
			dnl
			dnl Default is linking against the shared libcrafter
			dnl
			saved_LIBS=$LIBS
			LIBS="$LIBS -lcrafter -lpcap -lresolv"
			AC_MSG_CHECKING([for libcrafter])
			AC_LINK_IFELSE([
					AC_LANG_PROGRAM(
						[#include<crafter.h>],
						[Crafter::RawLayer hello("hello");]
					)],
					[
					CRAFTER_MODE="shared"
					CRAFTER_LIBS="-lcrafter -lpcap -lresolv"
					AC_MSG_RESULT([yes])
					],
					[
					AC_MSG_RESULT([no])
					AC_MSG_FAILURE([could not find or link against libcrafter.])
					]
			)
			LIBS=$saved_LIBS
		fi

		saved_LIBS=$LIBS
		LIBS="$LIBS $CRAFTER_LIBS"
		AC_MSG_CHECKING([for libcrafter > 0.2])
		AC_LINK_IFELSE([
				AC_LANG_PROGRAM(
					[#include<crafter.h>],
					[Crafter::Packet hello;hello.SubPacket(0, 0);]
				)],
				[
				AC_MSG_RESULT([yes])
				],
				[
				AC_MSG_RESULT([no])
				AC_MSG_FAILURE([Requires libcrafter version > 0.2.
					
Recommend downloading latest version from: https://github.com/pellegre/libcrafter])
				]
		)
		LIBS=$saved_LIBS
	
		dnl
		dnl Export flags.
		dnl
		AC_SUBST([CRAFTER_MODE])
		AC_SUBST([CRAFTER_LIBS])
		AC_SUBST([CRAFTER_CXXFLAGS])
		AC_SUBST([CRAFTER_LDFLAGS])
])
