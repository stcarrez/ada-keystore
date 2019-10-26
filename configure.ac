dnl Autoconf configure script for keystore

dnl Process this file with autoconf to produce a configure script.

AC_INIT(src/keystore.ads)

# Current release settings
KEYSTORE_MAJOR_VERSION=0
KEYSTORE_MINOR_VERSION=2
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

AM_GNAT_LIBRARY_PROJECT(keystore)
AM_GNAT_FIND_ADA_UTIL([Ada Keystore])

##########################################
# Ada LibSecret library
##########################################
HAVE_SECRETADA='no'
AM_GNAT_CHECK_PROJECT([secretada],[secretada])
if test $ac_cv_gnat_project_secretada = 'yes'; then
  SECRETADA_DIR=${gnat_project_dir_secretada}
  HAVE_SECRETADA='yes'
fi
AC_SUBST(SECRETADA_DIR)
AC_SUBST(HAVE_SECRETADA)

##########################################
# Ada LibSecret library
##########################################
AM_GNAT_CHECK_PROJECT([secretada],[secretada])

if test T$gnat_project_secretada = Tno; then
  WITH_SECRETADA='';
  HAVE_SECRETADA='no';
else
  WITH_SECRETADA="with \"${SECRETADA_DIR}secretada\";";
  HAVE_SECRETADA='yes';
fi
AC_SUBST(WITH_SECRETADA)
AC_SUBST(SECRETADA_DIR)
AC_SUBST(HAVE_SECRETADA)

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
