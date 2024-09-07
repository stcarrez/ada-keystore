# Installation

This chapter explains how to build and install the library.

## Before Building

To build the Ada Keystore you will need the GNAT Ada compiler as well
as the [Alire](https://alire.ada.dev/) package manager.

### Ubuntu

Install the following packages:
```
sudo apt-get install -y make gnat gprbuild git gnupg2 alr
```

### FreeBSD 13

Install the following packages:

```
pkg install gmake gprbuild gnat12 git gnupg alire
```

### Windows

Get the Alire package manager [Alire](https://alire.ada.dev/) site and install.

Install the following packages:

```
pacman -S git
pacman -S make
pacman -S base-devel --needed
```

## Getting the sources

You should checkout the project with the following commands:

```
git clone https://gitlab.com/stcarrez/ada-keystore.git
cd ada-keystore
```

## Build

You can build the library by running:
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


