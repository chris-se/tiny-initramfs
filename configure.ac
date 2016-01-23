AC_PREREQ([2.64])
AC_INIT([tiny-initramfs],
        [0.1],
        [https://github.com/chris-se/tiny-initramfs/issues],
        [tiny-initramfs],
        [https://github.com/chris-se/tiny-initramfs])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall dist-xz no-dist-gzip dist-lzip])
AM_SILENT_RULES([yes])
: ${CFLAGS="-Os"}
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
])
AC_ARG_ENABLE([uuid], [AS_HELP_STRING([--disable-uuid], [Enable support for searching for devices via their UUID (default is yes)])])
AS_IF([test x"$enable_uuid" != x"no"], [AC_DEFINE([ENABLE_UUID], [1], [Define if UUID support is enabled])])
AC_ARG_ENABLE([nfs4], [AS_HELP_STRING([--enable-nfs4], [Enable support for mounting NFSv4 shares (default is no)])])
AS_IF([test x"$enable_nfs4" = x"yes"], [AC_DEFINE([ENABLE_NFS4], [1], [Define if NFS4 support is enabled])])
AM_CONDITIONAL([ENABLE_NFS4], [test x"$enable_nfs4" = x"yes"])
AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [Enable support for printing debug messages])])
AS_IF([test x"$enable_debug" = x"yes"], [AC_DEFINE([ENABLE_DEBUG], [1], [Define if debug messages are enabled])])
AC_ARG_ENABLE([modules], [AS_HELP_STRING([--enable-modules], [Enable support for loading modules (default is no)])])
AS_IF([test x"$enable_modules" = x"yes"], [
  AC_CHECK_FUNC([finit_module], [AC_DEFINE([HAVE_FINIT_MODULE], [1], [Defined if finit_module is available.])], [])
  AC_MSG_CHECKING([for SYS_finit_module])
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <unistd.h>
    #include <sys/syscall.h>
    int a =
    #ifdef SYS_finit_module
    42
    #endif
    ;]])],[
      ac_cv_have_sys_finit_module=yes
      AC_DEFINE([HAVE_SYS_FINIT_MODULE], [1], [Defined if SYS_finit_module is available.])
      AC_MSG_RESULT([yes])
    ], [AC_MSG_RESULT([no])])
  AC_CHECK_FUNC([init_module])
  AS_IF([test x"$ac_cv_func_init_module" != x"yes" && test x"$ac_cv_have_sys_finit_module" != x"yes" && test x"$ac_cv_func_finit_module" != x"yes"],
        [AC_MSG_ERROR([Neither finit_module nor SYS_finit_module nor init_module syscalls available.])
  ])
  AC_DEFINE([ENABLE_MODULES], [1], [Define if support for loading modules is enabled])
])
AC_ARG_WITH([variant-name], [AS_HELP_STRING([--with-variant-name=NAME], [The variant name of the installed binary (default: none)])])
AS_IF([test x"$with_variant_name" != x""], [
  AC_DEFINE([VARIANT], ["$with_variant_name"], [The installed binary variant name])
  AC_SUBST([VARIANT], ["$with_variant_name"])
])
AM_CONDITIONAL([HAVE_VARIANT], [test x"$with_variant_name" != x""])

# Check for harmful CFLAGS in our build and warn the user.
AS_CASE([$CFLAGS], [*-O[[12345\ ]]*],
        [AC_MSG_WARN([optimization level other than -Os specified in CFLAGS, this will increase your binary size.])], [])
AS_CASE([$CFLAGS], [*-Os*],
        [], [AC_MSG_WARN([optimization level -Os not specified in CFLAGS, this will increase your binary size.])])
AS_CASE([$CFLAGS], [*\ -g*],
        [AC_MSG_WARN([debugging option -g specified in CFLAGS, this will increase your binary size.])], [])
AS_CASE([$CFLAGS], [-g*],
        [AC_MSG_WARN([debugging option -g specified in CFLAGS, this will increase your binary size.])], [])

# Check if the user links against glibc.
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <features.h>
int a =
#ifdef __GLIBC__
42
#endif
;]])], [AC_MSG_WARN([you are using glibc, binaries will be huge. Consider using an alternativ libc implementation (e.g. dietlibc, musl) instead.])], [])

AC_OUTPUT
