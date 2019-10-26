# Ada Keystore

[![Build Status](https://img.shields.io/jenkins/s/http/jenkins.vacs.fr/Bionic-Ada-Keystore.svg)](http://jenkins.vacs.fr/job/Bionic-Ada-Keystore/)
[![Test Status](https://img.shields.io/jenkins/t/http/jenkins.vacs.fr/Bionic-Ada-Keystore.svg)](http://jenkins.vacs.fr/job/Bionic-Ada-Keystore/)
[![License](http://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-keystore/0.2.0.svg)
![semver](https://img.shields.io/badge/semver-2.0.0-blue.svg?cacheSeconds=2592000)

# TL;DR

AKT is a tool to store protect your sensitive information and documents by
encrypting them in secure keystore (AES-256, HMAC-256).

Create the keystore and protect it with your gpg key:
```
   akt -f secure.akt create --gpg <keyid>
```

Store a small content:
```
   akt -f secure.akt set bank.password 012345
```

Store a file, files in a directory or a tar file:
```
   akt -f secure.akt set -f contract.doc
   akt -f secure.akt set -r directory
   tar czf - . | akt -f secure.akt store backup
```

Edit a content with your $EDITOR:
```
   akt -f secure.akt edit bank.password
```

Get a content:
```
   akt -f secure.akt get bank.password
   akt -f secure.akt get -o contract.doc
   akt -f secure.akt extract backup | tar xzf -
```

# Overview

Ada Keystore is a library and tool to store information in secure wallets
and protect the stored information by encrypting the content.
It is necessary to know one of the wallet password to access its content.
Ada Keystore can be used to safely store passwords, credentials,
bank accounts and even documents.

Wallets are protected by a master key using AES-256 and the wallet
master key is protected by a user password.
The wallet defines up to 8 slots that identify
a password key that is able to unlock the master key.  To open a wallet,
it is necessary to unlock one of these 8 slots by providing the correct
password.  Wallet key slots are protected by the user's password
and the PBKDF2-HMAC-256 algorithm, a random salt, a random counter
and they are encrypted using AES-256.

Values stored in the wallet are protected by their own encryption keys
using AES-256.  A wallet can contain another wallet which is then
protected by its own encryption keys and passwords (with 8 independent slots).
Because the child wallet has its own master key, it is necessary to known
the primary password and the child password to unlock the parent wallet
first and then the child wallet.

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

* `create`:   create the keystore
* `edit`:     edit the value with an external editor
* `get`:      get a value from the keystore
* `extract`:  get a value from the keystore
* `help`:     print some help
* `list`:     list values of the keystore
* `remove`:   remove values from the keystore
* `set`:      insert or update a value in the keystore
* `store`:    insert or update a value in the keystore

## Simple usage

To create the secure file, use the following command and enter
your secure password (it is recommended to use a long and complex password):

```
   akt -f secure.akt create
```

At this step, the secure file is created and it can only be opened
by providing the password you entered.  To add something, use:

```
   akt -f secure.akt set bank.password 012345
```

To store a file, use the following command:
```
   akt -f secure.akt set my-contract -f contract.doc
```

If you want to retrieve a value, you can use one of:
```
   akt -f secure.akt get bank.password
   akt -f secure.akt get -n my-contract > file.doc
```

The `store` and `extract` commands are intended to be used to store
and extract files produces by other tools such at
.IR tar (1).  For example, the output produced by
.I tar
can be stored using the following command:

```
   tar czf - . | akt -f secure.akt store backup.tar.gz
```

And it can be extracted by using the following command:

```
   akt -f secure.akt extract backup.tar.gz | tar xzf -
```

## Advanced usage

Even though the encryption keys are protected by a password,
it is sometimes useful to avoid exposing them and keep them separate
from the data blocks.  This is possible by using the `-d data-path`
option when the keystore file is created.  When this option is used,
the data blocks are written in one or several storage files located
in the directory.  To use this, create the keystore as follows:

```
   akt -f secure.akt -d data create
```

Then, you can do your backup by using:

```
   tar czf - . | akt -f secure.akt -d data store backup.tar.gz
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
   akt -f secure.akt -d data create --gpg your-gpg-key-id
```


# Building Ada Keystore

To configure Ada Keystore, use the following command:
```
   ./configure
```

The GTK application is not compiled by default unless to configure with
the `--enable-gtk` option.

```
   ./configure  --enable-gtk
```

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
   root@...:/usr/src# akt -f secure.akt create
   root@...:/usr/src# akt -f secure.akt set something some-secret
   root@...:/usr/src# akt -f secure.akt get something
```

# Documents

* Man page: [akt (1)](https://github.com/stcarrez/ada-keystore/blob/master/docs/akt.md)

# References

* [RFC8018: PKCS #5: Password-Based Cryptography Specification Version 2.1](https://tools.ietf.org/html/rfc8018)
* [Meltem Sönmez Turan, Elaine Barker, William Burr, and Lily Chen. "NIST SP 800-132, Recommendation for Password-Based Key Derivation Part 1: Storage Applications" (PDF). www.nist.gov.](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
* [FIPS PUB 198-1, The Keyed-Hash Message Authentication Code (HMAC)](https://csrc.nist.gov/csrc/media/publications/fips/198/1/final/documents/fips-198-1_final.pdf)

