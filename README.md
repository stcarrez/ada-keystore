# Ada Keystore

[![Build Status](https://img.shields.io/jenkins/s/http/jenkins.vacs.fr/Bionic-Ada-Keystore.svg)](http://jenkins.vacs.fr/job/Bionic-Ada-Keystore/)
[![Test Status](https://img.shields.io/jenkins/t/http/jenkins.vacs.fr/Bionic-Ada-Keystore.svg)](http://jenkins.vacs.fr/job/Bionic-Ada-Keystore/)
[![License](http://img.shields.io/badge/license-APACHE2-blue.svg)](LICENSE)
![Commits](https://img.shields.io/github/commits-since/stcarrez/ada-keystore/1.0.0.svg)
![semver](https://img.shields.io/badge/semver-2.0.0-blue.svg?cacheSeconds=2592000)

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

# Documents

* Man page: [akt (1)](https://github.com/stcarrez/ada-keystore/blob/master/docs/akt.md)

# References

* [RFC8018: PKCS #5: Password-Based Cryptography Specification Version 2.1](https://tools.ietf.org/html/rfc8018)
* [Meltem Sönmez Turan, Elaine Barker, William Burr, and Lily Chen. "NIST SP 800-132, Recommendation for Password-Based Key Derivation Part 1: Storage Applications" (PDF). www.nist.gov.](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
* [FIPS PUB 198-1, The Keyed-Hash Message Authentication Code (HMAC)](https://csrc.nist.gov/csrc/media/publications/fips/198/1/final/documents/fips-198-1_final.pdf)

