#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([daq_example],[1.0],[BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE()
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_example.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
LT_INIT

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])

# Custom include/library path specifications

# Substitutions
AC_SUBST([LIBS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AC_MSG_RESULT([
    $PACKAGE $VERSION
    ========

    prefix:         ${prefix}
    sysconfdir:     ${sysconfdir}
    libdir:         ${libdir}
    includedir:     ${includedir}

    compiler:       ${CC}
    cflags:         ${CFLAGS}
    cppflags:       ${CPPFLAGS}
    ldflags:        ${LDFLAGS}
    libs:           ${LIBS}

    am_cppflags:    ${AM_CPPFLAGS}
    am_cflags:      ${AM_CFLAGS}
    am_ldflags:     ${AM_LDFLAGS}
])
