dnl Autoconf configure script for keystore

dnl Process this file with autoconf to produce a configure script.

AC_INIT
AC_CONFIG_SRCDIR([src/keystore.ads])

# Current release settings
KEYSTORE_MAJOR_VERSION=1
KEYSTORE_MINOR_VERSION=3
KEYSTORE_MICRO_VERSION=4
KEYSTORE_VERSION=$KEYSTORE_MAJOR_VERSION.$KEYSTORE_MINOR_VERSION.$KEYSTORE_MICRO_VERSION

# Set the version number of the project
AC_SUBST(KEYSTORE_VERSION)
AC_SUBST(KEYSTORE_MAJOR_VERSION)
AC_SUBST(KEYSTORE_MINOR_VERSION)
AC_SUBST(KEYSTORE_MICRO_VERSION)

EXEC_PREFIX="$prefix"
AC_SUBST(EXEC_PREFIX)
AC_CHECK_PROG(HAVE_PANDOC,pandoc,yes)
AC_CHECK_PROG(HAVE_DYNAMO,dynamo,yes)

AM_GNAT_LIBRARY_PROJECT(keystoreada)

AC_MSG_CHECKING([External Ada Utility Library])
AC_ARG_WITH(ada-util,
AS_HELP_STRING([--with-ada-util=x], [Path for Ada Utility Library]),
[
  if test T${withval} = Tno ; then
    KEYSTORE_USE_ADA_UTIL=no;
  else
    KEYSTORE_USE_ADA_UTIL='yes';
  fi
],
[
  if test T${awa_build_root} = T ; then
    KEYSTORE_USE_ADA_UTIL='no';
  else
    KEYSTORE_USE_ADA_UTIL='yes';
  fi
])
AC_MSG_RESULT(${KEYSTORE_USE_ADA_UTIL})

AM_GNAT_CHECK_PROJECT([utilada_sys],[utilada_sys])
if test T$ac_cv_gnat_project_utilada_sys = Tno; then

  if test T${KEYSTORE_USE_ADA_UTIL} = Tyes; then
    AM_GNAT_FIND_PROJECT([ada-util],[Ada Utility Library],[utilada_base],
    [git@github.com:stcarrez/ada-util.git],
    [Building Ada Keystore requires the Ada Utility Library.],
    [
      UTIL_DIR=${ac_cv_gnat_project_dir_utilada_base}
    ])
    WITH_ADA_UTIL="with \"${UTIL_DIR}utilada_core\";";
    WITH_ADA_UTIL_SYS="with \"${UTIL_DIR}utilada_base\";";
  else
    WITH_ADA_UTIL=''
    WITH_ADA_UTIL_SYS=''
    UTIL_DIR='./ada-util/'

    ac_configure_args="${ac_configure_args} --disable-lzma --disable-aws --disable-curl --with-xmlada=no --with-build-root="`pwd`

    AC_CONFIG_SUBDIRS(ada-util)
  fi
else
  AM_GNAT_FIND_ADA_UTIL([Ada Keystore])
fi

AC_SUBST(UTIL_DIR)
AC_SUBST(WITH_ADA_UTIL)
AC_SUBST(WITH_ADA_UTIL_SYS)
AC_SUBST(KEYSTORE_USE_ADA_UTIL)

case "${target_os}" in
  mingw32*|cygwin*|mingw64*|msys)
    HAVE_GETTEXT=False
    GETTEXT_INTL=False
    ;;

  *)
    AM_GNU_GETTEXT([external])
    ;;

esac

if test T$HAVE_GETTEXT = TTrue; then
  USE_NLS=yes
else
  USE_NLS=no
fi
AC_SUBST(USE_NLS)


if test T$GETTEXT_INTL = TTrue; then
  USE_LIBINTL=yes
else
  USE_LIBINTL=no
fi
AC_SUBST(USE_LIBINTL)

##########################################
# GtkAda library
##########################################
ac_enable_gtk=no
AC_ARG_ENABLE(gtk,
[  --enable-gtk            enable compilation of Gtk tool (disabled)],
[case "${enableval}" in
  no|none)  ac_enable_gtk= ;;
  *)        ac_enable_gtk=yes
esac])dnl

AC_MSG_CHECKING([whether GtkAda is enabled])
AC_MSG_RESULT($ac_enable_gtk)

GTKADA_DIR=
if test x$ac_enable_gtk = 'xyes'; then
  AM_GNAT_FIND_PROJECT([gtkada],[Gtk Ada Library],[gtkada],
    [libre.adacore.com/tools/gtkada],
    [Building Ada Keystore requires the Gtk Ada Library.],
    [
      GTKADA_DIR=${ac_cv_gnat_project_dir_gtkada}
    ])
fi

HAVE_GTK=$ac_enable_gtk
AC_SUBST(HAVE_GTK)

AC_SUBST(GTKADA_DIR)

if test -f ada-fuse/ada_fuse.gpr; then
   case "${target_os}" in
      mingw32*|cygwin*|mingw64*|msys)
        ac_enable_fuse=no
        ;;

      *)
        ac_enable_fuse=yes
       ;;

    esac
else
   ac_enable_fuse=no
fi

AC_ARG_ENABLE(fuse,
[  --enable-fuse           enable support for Fuse (disabled)],
[case "${enableval}" in
  no|none)
     ac_enable_fuse=no
     USE_GIT_FUSE=no
     ;;
  *)
     ac_enable_fuse=yes
esac])dnl

AC_MSG_CHECKING([whether Fuse is enabled])
AC_MSG_RESULT($ac_enable_fuse)

if test ${ac_enable_fuse} = 'yes'; then
   FUSEADA_DIR=ada-fuse
   WITH_FUSE_ADA='with "ada-fuse/ada_fuse";'
   USE_GIT_FUSE=yes
else
   FUSEADA_DIR=
   USE_GIT_FUSE=no
   WITH_FUSE_ADA=''
fi
AC_SUBST(USE_GIT_FUSE)

if test x$ac_enable_fuse = 'xyes'; then
  AC_CHECK_PROG(HAVE_PKG_CONFIG,pkg-config,yes)
  if test x$HAVE_PKG_CONFIG != 'xyes'; then
    AC_MSG_ERROR([Please install pkg-config when fuse support is enabled.])     
  fi

  AC_MSG_CHECKING([whether Fuse is supported])
  if AC_TRY_COMMAND([pkg-config --libs fuse > /dev/null 2>conftest.out])
  then
    ac_enable_fuse=yes
  else
    ac_enable_fuse=no
    USE_GIT_FUSE=no
    FUSEADA_DIR=
    WITH_FUSE_ADA=''
  fi
  AC_MSG_RESULT($ac_enable_fuse)
fi

if test x$ac_enable_fuse = 'xyes' && test x$FUSEADA_DIR = 'x'; then
  if test x$USE_GIT_FUSE = 'xno'; then
   AM_GNAT_FIND_PROJECT([ada-fuse],[Fuse Ada Library],[ada_fuse],
    [git@github.com:medsec/ada-fuse.git],
    [Building Ada Keystore requires the Ada Fuse Library.],
    [
      FUSEADA_DIR=${ac_cv_gnat_project_dir_ada_fuse}
      WITH_FUSE_ADA=${ac_cv_gnat_project_with_ada_fuse}
    ])
  fi
fi

HAVE_FUSE=$ac_enable_fuse
AC_SUBST(HAVE_FUSE)
AC_SUBST(WITH_FUSE_ADA)

AC_CONFIG_FILES([Makefile.conf
keystoreada.gpr
keystoreada_tools.gpr
keystoreada_tests.gpr
keystoreada_gtk.gpr
])
AC_OUTPUT
