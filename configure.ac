m4_include([VERSION])

AC_PREREQ([2.69])
AC_INIT([btcblock],
m4_esyscmd_s(cat VERSION),
[29279974+sdev75@users.noreply.github.com])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_AUX_DIR([.build-aux])
AC_CONFIG_MACRO_DIR([.build-m4])

AC_CANONICAL_HOST
AH_TOP([#ifndef CONFIG_H])
AH_TOP([#define CONFIG_H])
AH_BOTTOM([#endif //CONFIG_H])

AM_INIT_AUTOMAKE([1.13 no-define foreign subdir-objects])

AC_CHECK_HEADERS([stdlib.h, stdint.h, endian.h, sys/endian.h])

# Checks for programs.
AC_PROG_CXX

AC_LANG_PUSH([C++])
AX_CHECK_COMPILE_FLAG([-Werror],[CXXFLAG_WERROR="-Werror"],[CXXFLAG_WERROR=""])

AM_SILENT_RULES([yes])
AX_CXX_COMPILE_STDCXX([17], [noext], [mandatory])

LT_PREREQ([1.5.2])
LT_INIT([pic-only])

dnl Check for endianness
AC_C_BIGENDIAN

AX_PTHREAD

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [use compiler flags and macros suited for debugging (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])


if test "x$enable_debug" = xyes; then
  dnl Clear default -g -O2 flags
	CXXFLAGS=""

  dnl Disable all optimizations
  AX_CHECK_COMPILE_FLAG([-O0], [[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -O0"]],,[[$CXXFLAG_WERROR]])

  dnl Prefer -g3, fall back to -g if that is unavailable.
  AX_CHECK_COMPILE_FLAG(
    [-g3],
    [[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g3"]],
    [AX_CHECK_COMPILE_FLAG([-g],[[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g"]],,[[$CXXFLAG_WERROR]])],
    [[$CXXFLAG_WERROR]])

  AX_CHECK_PREPROC_FLAG([-DDEBUG],[[DEBUG_CPPFLAGS="$DEBUG_CPPFLAGS -DDEBUG"]],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-ftrapv],[DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -ftrapv"],,[[$CXXFLAG_WERROR]])
fi


AX_CHECK_COMPILE_FLAG([-Werror=unused-variable],[ERROR_CXXFLAGS="$ERROR_CXXFLAGS -Werror=unused-variable"],,[[$CXXFLAG_WERROR]])
AX_CHECK_COMPILE_FLAG([-Werror=date-time],[ERROR_CXXFLAGS="$ERROR_CXXFLAGS -Werror=date-time"],,[[$CXXFLAG_WERROR]])
AX_CHECK_COMPILE_FLAG([-Werror=return-type],[ERROR_CXXFLAGS="$ERROR_CXXFLAGS -Werror=return-type"],,[[$CXXFLAG_WERROR]])
AX_CHECK_COMPILE_FLAG([-Werror=sign-compare],[ERROR_CXXFLAGS="$ERROR_CXXFLAGS -Werror=sign-compare"],,[[$CXXFLAG_WERROR]])
AX_CHECK_COMPILE_FLAG([-Wfatal-errors],[ERROR_CXXFLAGS="$ERROR_CXXFLAGS -Wfatal-errors"],,[[$CXXFLAG_WERROR]])


#AC_DEFINE([_POSIX_C_SOURCE], [200809L], [Support for clock])

AC_CONFIG_FILES([
  Makefile 
  src/Makefile 
  test/Makefile 
  utils/crypto/Makefile 
  utils/crypto/btc/Makefile 
])
AC_OUTPUT
cat << EOF
-------------------------------------------------

Summary:

${PACKAGE_NAME} ${PACKAGE_VERSION}

            CC     = $CC
        CFLAGS     = $CFLAGS
      CPPFLAGS     = $DEBUG_CPPFLAGS $CPPFLAGS
           CXX     = $CXX
      CXXFLAGS     = $DEBUG_CXXFLAGS $ERROR_CXXFLAGS $CXXFLAGS
       LDFLAGS     = $PTHREAD_CFLAGS $LDFLAGS
       ARFLAGS     = $ARFLAGS
 Debug Enabled     = $enable_debug
  
--------------------------------------------------
EOF
