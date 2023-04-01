# Ada Keystore

[![Alire](https://img.shields.io/endpoint?url=https://alire.ada.dev/badges/keystoreada.json)](https://alire.ada.dev/crates/keystoreada)
[![Build Status](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-keystore/badges/build.json)](https://porion.vacs.fr/porion/projects/view/ada-keystore/summary)
[![Test Status](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-keystore/badges/tests.json)](https://porion.vacs.fr/porion/projects/view/ada-keystore/xunits)
[![Coverage](https://img.shields.io/endpoint?url=https://porion.vacs.fr/porion/api/v1/projects/ada-keystore/badges/coverage.json)](https://porion.vacs.fr/porion/projects/view/ada-keystore/summary)
[![Documentation Status](https://readthedocs.org/projects/ada-keystore/badge/?version=latest)](https://ada-keystore.readthedocs.io/en/latest/?badge=latest)
[![Download](https://img.shields.io/badge/download-1.3.3-brightgreen.svg)](http://download.vacs.fr/ada-keystore/ada-keystore-1.3.3.tar.gz)
[![License](http://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-keystore/1.3.3.svg)
[![GitLab](https://img.shields.io/badge/repo-GitLab-6C488A.svg)](https://gitlab.com/stcarrez/ada-keystore)
![semver](https://img.shields.io/badge/semver-2.0.0-blue.svg?cacheSeconds=2592000)

# TL;DR

AKT is a tool to store and protect your sensitive information and documents by
encrypting them in secure keystore (AES-256, HMAC-256).

Create the keystore and protect it with a gpg public key:
```
   akt create secure.akt --gpg <keyid> ...
```

Store a small content:
```
   akt set secure.akt bank.password 012345
```

Store files, directory or a tar file:
```
   akt store secure.akt notes.txt
   akt store secure.akt contract.doc
   akt store secure.akt directory
   tar czf - . | akt store secure.akt -- backup
```

Edit a content with your $EDITOR:
```
   akt edit secure.akt bank.password
   akt edit secure.akt notes.txt
```

Get a content:
```
   akt get secure.akt bank.password
   akt extract secure.akt contract.doc
   akt extract secure.akt -- backup | tar xzf -
```

Mount the keystore:
```
   akt mount secure.akt /mnt
   # access the keystore content in /mnt
   umount /mnt
```

Store a new OTP secret:
```
   akt otp secure.akt otpauth://totp/GitHub:...
```

Generate the TOTP code:
```
   akt otp secure.akt GitHub
```


## Version 1.4.0  - Under development
  - Feature #15: Authenticator with TOTP support
  - Fix #16: Support to build with -gnatW8
  - Fix #17: Test with corrupted data block sometimes dump the corrupted data
  - New genkey and otp commands

## Version 1.3.4  - Feb 2023
- Fix #14: Constraint_Error raised if the HOME environment variable is not defined
- Fix fuse detection on FreeBSD
- Fix building docker image

[List all versions](https://github.com/stcarrez/ada-keystore/blob/master/NEWS.md)

# Overview

Ada Keystore is a tool and library to store information in secure wallets
and protect the stored information by encrypting the content.
It is necessary to know one of the wallet password to access its content.
Ada Keystore can be used to safely store passwords, credentials,
bank accounts and even documents.

Wallets are protected by a master key using AES-256 and the wallet
master key is protected by a user password.
The wallet defines up to 7 slots that identify
a password key that is able to unlock the master key.  To open a wallet,
it is necessary to unlock one of these 7 slots by providing the correct
password.  Wallet key slots are protected by the user's password
and the PBKDF2-HMAC-256 algorithm, a random salt, a random counter
and they are encrypted using AES-256.

Values stored in the wallet are protected by their own encryption keys
using AES-256.  A wallet can contain another wallet which is then
protected by its own encryption keys and passwords (with 7 independent slots).
Because the child wallet has its own master key, it is necessary to known
the primary password and the child password to unlock the parent wallet
first and then the child wallet.

![AKT Overview](https://github.com/stcarrez/ada-keystore/wiki/images/akt-overview.png)

The data is organized in blocks of 4K whose primary content is encrypted
either by the wallet master key or by the entry keys.  The data block is
signed by using HMAC-256.  A data block can contain several values but
each of them is protected by its own encryption key.  Each value is also
signed using HMAC-256.

The tool is able to separate the data blocks from the keys and use
a specific file to keep track of keys and one or several files for
the data blocks.  When data blocks are separate from the keys, it is
possible to copy the data files on other storages without exposing
any key used for encryption.  The data storage files use the `.dkt`
extension and they are activated by using the `-d data-path` option.

# Using Ada Keystore Tool

The `akt` tool is the command line tool that manages the wallet.
It provides the following commands:

* `config`:   setup some global configuration
* `create`:   create the keystore
* `edit`:     edit the value with an external editor
* `extract`:  get a value from the keystore
* `genkey`:   generate or manage named keys
* `get`:      get a value from the keystore
* `help`:     print some help
* `info`:     print information about the keystore
* `list`:     list values of the keystore
* `mount`:    mount the keystore on the filesystem for a direct access
* `otp`:      generate a one time password or manage OATH secrets
* `password-add`:      add a password
* `password-remove`:   remove a password
* `password-set`:      change the password
* `remove`:   remove values from the keystore
* `set`:      insert or update a value in the keystore
* `store`:    insert or update a value in the keystore

## Simple usage

To create the secure file, use the following command and enter
your secure password (it is recommended to use a long and complex password):

```
   akt create secure.akt
```

At this step, the secure file is created and it can only be opened
by providing the password you entered.  To add something, use:

```
   akt set secure.akt bank.password 012345
```

To store a file, use the following command:
```
   akt store secure.akt contract.doc
```

If you want to retrieve a value, you can use one of:
```
   akt get secure.akt bank.password
   akt extract secure.akt contract.doc
```

The `store` and `extract` commands are intended to be used to store
and extract files produced by other tools such at
.IR tar (1).  For example, the output produced by
.I tar
can be stored using the following command:

```
   tar czf - . | akt store secure.akt -- backup.tar.gz
```

And it can be extracted by using the following command:

```
   akt extract secure.akt -- backup.tar.gz | tar xzf -
```

## Advanced usage

Even though the encryption keys are protected by a password,
it is sometimes useful to avoid exposing them and keep them separate
from the data blocks.  This is possible by using the `-d data-path`
option when the keystore file is created.  When this option is used,
the data blocks are written in one or several storage files located
in the directory.  To use this, create the keystore as follows:

```
   akt create secure.akt -d data
```

Then, you can do your backup by using:

```
   tar czf - . | akt store secure.akt -d data -- backup.tar.gz
```

The tool will put in `secure.akt` all the encryption keys and it will
create in the `data` directory the files that contain the data blocks.
You can then copy these data blocks on a backup server.  They don't contain
any encryption key.  Because each 4K data block is encrypted by its own
key, it is necessary to know all the keys to be able to decrypt the full
content.  The `secure.akt` file is the only content that contains
encryption keys.

## Using GPG to protect the keystore

You can use GPG to lock/unlock the keystore.  To do this, you have
to use the `--gpg` option and giving your own GPG key identifier
(or your user's name).

```
   akt create secure.akt -d data --gpg your-gpg-key-id
```

You can also share the keystore with someone else provided you know
and trust the foreign public key.  To do that, you can create the keystore
and defined the GPG key for each user you want to share the keystore:

```
   akt create secure.akt -d data --gpg user1-key user2-key user3-key
```

To unlock the keystore, GPG will use the private key.

## Mounting the keystore on the filesystem

The keystore content can be mounted as a filesystem so that the
encrypted content are directly available to existing application
as regular files.  The `mount` command starts the fuse daemon
and puts the command as a background fuse daemon to serve as
a fuse filesystem and make the content visible through the
mount point.

```
   akt mount secure.akt /mnt
```

To unmount the filesystem, you must use the `umount` command.

```
   umount /mnt
```

Sometimes, you may have to force the umount by running:

```
   sudo umount /mnt
```

# AKT Debian Binaries

Ubuntu 22.04 packages are available to help you install the `akt` command
more easily.  You can configure your Ubuntu system as follows:

```
wget -O - https://apt.vacs.fr/apt.vacs.fr.gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://apt.vacs.fr/ubuntu-jammy jammy main"
```

And then install the `akt` package:

```
sudo apt-get install akt
```


# Building Ada Keystore

To build the Ada Keystore you will need the GNAT Ada compiler, either
the FSF version available in Debian, FreeBSD systems NetBSD or the
AdaCore GNAT Community 2019 edition.

## Development Host Installation

### Ubuntu

Install the following packages:
```
sudo apt-get install -y make gnat-7 gprbuild git gnupg2
```

### FreeBSD 13

Install the following packages:

```
pkg install gmake gnat12 gprbuild gnupg
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
   git clone --recursive https://github.com/stcarrez/ada-keystore.git
   cd ada-keystore
```

## Configuration

To configure Ada Keystore, use the following command:
```
   ./configure
```

The GTK application is not compiled by default unless to configure with
the `--enable-gtk` option.  Be sure to install the GtkAda library before
configuring and building the project.

```
   ./configure  --enable-gtk
```

## Build

Then, build the application:
```
   make
```

And install it:
```
   make install
```

# Docker

A docker container is available for those who want to try AKT without
installing and building the required Ada packages.
To use the AKT docker container you can run the following commands:

```
   docker pull ciceron/ada-keystore
   docker run -i -t --entrypoint /bin/bash ciceron/ada-keystore
   root@...:/usr/src# akt create secure.akt
   root@...:/usr/src# akt set secure.akt something some-secret
   root@...:/usr/src# akt get secure.akt something
```

# Documents

* [Ada Keystore Guide](https://ada-keystore.readthedocs.io/en/latest/) [PDF](https://github.com/stcarrez/ada-keystore/blob/master/docs/keystoreada-book.pdf)
* Man page: [akt (1)](https://github.com/stcarrez/ada-keystore/blob/master/docs/akt.md)

# Presentations

* [AKT un outil pour sécuriser vos données et documents sensibles](https://fr.slideshare.net/StephaneCarrez1/akt-un-outil-pour-scuriser-vos-donnes-et-documents-sensibles) Paris Open Source Summit 2019
* [Protect Sensitive Data with Ada Keystore](https://fr.slideshare.net/StephaneCarrez1/protect-sensitive-data-with-ada-keystore) Ada devroom FOSDEM 2020


# References

* [RFC8018: PKCS #5: Password-Based Cryptography Specification Version 2.1](https://tools.ietf.org/html/rfc8018)
* [Meltem Sönmez Turan, Elaine Barker, William Burr, and Lily Chen. "NIST SP 800-132, Recommendation for Password-Based Key Derivation Part 1: Storage Applications" (PDF). www.nist.gov.](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
* [FIPS PUB 198-1, The Keyed-Hash Message Authentication Code (HMAC)](https://csrc.nist.gov/csrc/media/publications/fips/198/1/final/documents/fips-198-1_final.pdf)
* [FIPS PUB 197, Advanced Encryption Standard (AES)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

