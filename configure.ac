dnl Autoconf configure script for keystore

dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/keystore.ads)

# Current release settings
KEYSTORE_MAJOR_VERSION=1
KEYSTORE_MINOR_VERSION=0
KEYSTORE_MICRO_VERSION=0
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

if test T${KEYSTORE_USE_ADA_UTIL} = Tyes; then
  AM_GNAT_FIND_PROJECT([ada-util],[Ada Utility Library],[utilada_sys],
  [git@github.com:stcarrez/ada-util.git],
  [Building Ada Keystore requires the Ada Utility Library.],
  [
    UTIL_DIR=${ac_cv_gnat_project_dir_utilada_sys}
  ])
  WITH_ADA_UTIL="with \"${UTIL_DIR}utilada_core\";";
  WITH_ADA_UTIL_SYS="with \"${UTIL_DIR}utilada_sys\";";
else
  WITH_ADA_UTIL=''
  WITH_ADA_UTIL_SYS=''
  UTIL_DIR='./ada-util/'

  ac_configure_args="${ac_configure_args} --with-build-root="`pwd`

  AC_CONFIG_SUBDIRS(ada-util)
fi
AC_SUBST(UTIL_DIR)
AC_SUBST(WITH_ADA_UTIL)
AC_SUBST(WITH_ADA_UTIL_SYS)
AC_SUBST(KEYSTORE_USE_ADA_UTIL)

AC_MSG_CHECKING([whether NLS is requested])
dnl Default is enabled NLS
AC_ARG_ENABLE(nls,
  [  --disable-nls           do not use Native Language Support],
  USE_NLS=$enableval, USE_NLS=yes)
AC_MSG_RESULT($USE_NLS)
AC_SUBST(USE_NLS)

ac_enable_gtk=no
AC_ARG_ENABLE(gtk,
[  --enable-gtk            enable compilation of Gtk tool (disabled)],
[case "${enableval}" in
  no|none)  ac_enable_gtk= ;;
  *)        ac_enable_gtk=yes
esac])dnl

GTKADA_DIR=
if test x$ac_enable_gtk = 'xyes'; then

##########################################
# GtkAda library
##########################################
AC_MSG_CHECKING([GtkAda library (libre.adacore.com/tools/gtkada)])
AC_ARG_WITH(gtkada,
AS_HELP_STRING([--with-gtkada=x], [Path for the Gtk Ada library (libre.adacore.com/tools/gtkada)]),
[
  GTKADA_DIR=${withval}/
],
[
  echo "with \"gtkada\"; project t is for Source_Dirs use (); end t;" > t.gpr
  gnatmake -p -Pt >/dev/null 2>/dev/null
  if test $? -eq 0; then
    GTKADA_DIR=
  else
    GTKADA_DIR=../gtkada/
  fi;
])
echo "with \"${GTKADA_DIR}gtkada\"; project t is for Source_Dirs use (); end t;" > t.gpr
gnatmake -p -Pt >/dev/null 2>/dev/null
if test $? -ne 0 ; then
   rm -f t.gpr
   ac_enable_gtk=
   # AC_MSG_ERROR([GtkAda library not found in ${GTKADA_DIR}])
 fi
rm -f t.gpr
AC_MSG_RESULT(${GTKADA_DIR})

fi

HAVE_GTK=$ac_enable_gtk
AC_SUBST(HAVE_GTK)

AC_SUBST(GTKADA_DIR)

AC_OUTPUT(
Makefile.conf
keystoreada.gpr
keystoreada_tools.gpr
keystoreada_tests.gpr
keystoreada_gtk.gpr
)
