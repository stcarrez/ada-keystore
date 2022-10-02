# Installation

This chapter explains how to build and install the library.

## Before Building

To build the Ada Keystore you will need the GNAT Ada compiler, either
the FSF version available in Debian, FreeBSD systems NetBSD or the
AdaCore GNAT Community 2019 edition.

### Ubuntu

Install the following packages:
```
sudo apt-get install -y make gnat gprbuild git gnupg2
```

### FreeBSD 12

Install the following packages:

```
pkg install gmake gcc6-aux-20180516_1,1 gprbuild-20160609_1 git gnupg-2.2.17_2
```

### Windows

Get the Ada compiler from [AdaCore Download](https://www.adacore.com/download)
site and install.

Install the following packages:

```
pacman -S git
pacman -S make
pacman -S base-devel --needed
```

## Getting the sources

The project uses a sub-module to help you in the integration and build
process.  You should checkout the project with the following commands:

```
   git clone --recursive https://gitlab.com/stcarrez/ada-keystore.git
   cd ada-keystore
```

## Configuration

The library uses the `configure` script to detect the build environment,
check which Ada Utility Library to use.
If some component is missing, the
`configure` script will report an error or it will disable the feature.
The `configure` script provides several standard options
and you may use:

  * `--prefix=DIR` to control the installation directory,
  * `--enable-fuse` to enable building the `mount` command with FUSE,
  * `--enable-gtk` to enable building the Gtk tool,
  * `--enable-shared` to enable the build of shared libraries,
  * `--disable-static` to disable the build of static libraries,
  * `--disable-nls` to disable NLS support,
  * `--with-ada-util=PATH` to control the installation path of [Ada Utility Library](https://github.com/stcarrez/ada-util),
  * `--with-gtkada=PATH` to control the installation path of [Gtk Ada Library](https://github.com/AdaCore/GtkAda),
  * `--help` to get a detailed list of supported options.

In most cases you will configure with the following command:
```
./configure
```

The GTK application is not compiled by default unless you configure with
the `--enable-gtk` option.  Be sure to install the GtkAda library before
configuring and building the project.

```
./configure  --enable-gtk
```

On Windows, FreeBSD and NetBSD you have to disable the NLS support:
```
./configure --disable-nls
```

## Build

After configuration is successful, you can build the library by running:
```
make
```

After building, it is good practice to run the unit tests before installing
the library.  The unit tests are built and executed using:
```
make test
```
And unit tests are executed by running the `bin/keystore_harness` test program.

## Installation
The installation is done by running the `install` target:

```
make install
```

If you want to install on a specific place, you can change the `prefix`
and indicate the installation direction as follows:

```
make install prefix=/opt
```

## Using

To use the library in an Ada project, add the following line at the
beginning of your GNAT project file:

```
with "keystoreada";
```


