# AKT Tool

## NAME

akt - Tool to protect your sensitive data with secure storage

## SYNOPSIS

*akt* [ -v ] [-vv] [-vv] [-V] [ -c
*config-file* ] [-t
*count* ] [-z]
*command*  [-k
*file* ] [ -d
*dir* ] [ -p
*password* ] [--password
*password* ] [--passfile
*file* ] [--passenv
*name* ] [--passfd
*fd* ] [--passask] [--passcmd
*cmd* ] [--passkey
*name* ] [--wallet-key-file
*file* ] [--wallet-key
*name* ]


## DESCRIPTION

**akt** is a tool to store information in secure wallets
and protect the stored information by encrypting the content.
It is necessary to know one of the wallet password to access its content.
**akt** can be used to safely store passwords, credentials,
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

The data is organized in blocks of 4K whose primary content is encrypted
either by the wallet master key or by the entry keys.  The data block is
signed by using HMAC-256.  A data block can contain several values but
each of them is protected by its own encryption key.  Each value is also
signed using HMAC-256.  Large values can be written to several data
blocks and in that case each fragment is encrypted by using its own
encryption key.

The tool provides several commands that allow to create a keystore,
insert values, retrieve values or delete them.  You can use it to
store your passwords, your secret keys and even your documents.

Passwords are retrieved using one of the following options:


* by reading a file that contains the password,

* by looking at an environment variable,

* by using a command line argument,

* by getting the password through the
**ssh-askpass**(1) external command,

* by running an external command,

* by asking interactively the user for the password,

* by asking through a network socket for the password.


## OPTIONS

The following options are recognized by **akt**:


-V
Prints the
*akt* version.


-v
Enable the verbose mode.


-vv
Enable debugging output.


-c
*config-file* Defines the path of the global
*akt* configuration file.


-t
*count* Defines the number of threads for the encryption and decryption process.
By default, it uses the number of system CPU cores.


-k file

Specifies the path of the keystore file to open.


-d directory

Specifies the directory path of the keystore data files.
When this option is used, the data blocks are written in separate
files.  The data blocks do not contain the encryption keys and each of
them is encrypted with its own secure key.


-p password

The keystore password is passed within the command line.
Using this method is convenient but is not safe.


--passenv envname

The keystore password is passed within an environment variable with the
given name.  Using this method is considered safer but still provides
some security leaks.


--passfile path

The keystore password is passed within a file that is read.
The file must not be readable or writable by other users or group:
its mode must be r??------.  The directory that contains the file
must also satisfy the not readable by other users or group members,
This method is safer and provides the same security level as the
*--passkey* option.


--passfd fd

The keystore password is passed within a pipe whose file descriptor
number is given.  The file descriptor is read to obtain the password.
This method is safer.


--passask

The keystore password is retrieved by the running the external tool
**ssh-askpass**(1) which will ask the password through either KDE, Gnome or another
desktop interactive application.
The password is retrieved through a pipe that
*akt* sets while launching the command.


--passcmd cmd

The keystore password is retrieved by the running the external command defined in
**cmd**. The command should print the password on its standard output without end of line.
The password is retrieved through a pipe that
*akt* sets while launching the command.


--passkey name

The keystore password is retrieved from a keyfile with the given basename.
The keyfile is created by the
*genkey* command and they are stored on the file system in a specific directory.
Unlike the
*--passfile* option, only the basename of the file is given to the option and this avoid
to give a full path name in some cases.
This provides the same security level as the
*--passfile* option.


--wallet-key-file file
Defines the path of a file which contains the wallet master key file.


--wallet-key name
Defines the name of the key file which contains the wallet master key.


-z
Erase and fill with zeros instead of random values.

## COMMANDS



### The create command
```
akt create keystore.akt [--force] [--counter-range min:max] [--split count] [--gpg user ...]
```

Create a new keystore and protect it with the password.  When the keystore
file already exist, the create operation will fail unless the
*--force* option is passed.

The password to protect the wallet is passed using one of the following options:
*--passfile*, *--passkey*, *--passenv*, *--password*, *--passsocket* or
*--gpg*. When none of these options are passed, the password is asked interactively.

The
*--counter-range* option allows to control the range for the random counter used by PBKDF2
to generate the encryption key derived from the specified password.
High values provide a strongest derived key at the expense of speed.
This option is ignored when the
*--gpg* option is used.

The
*--split* option indicates to use several separate files for the data blocks
and it controls the number of separate files to use.  When used, a
directory with the name of the keystore file is created and will contain
the data files.

The
*--gpg* option allows to protect the keystore by using a user's GPG encryption key.
The option argument defines the GPG user's name or GPG key.
When the keystore password is protected by the user's GPG key,
a random password is generated to protect the keystore.
The
**gpg2**(1) command is used to encrypt that password using the user's public key
and save it in the keystore header.  The
**gpg2**(1) command is then used to decrypt that and be able to unlock the keystore
provided that the user's private key is known.  When using the
*--gpg* option, it is possible to protect the keystore for several users, thus
being able to share the secure file with each of them.


### The extract command
```
akt extract keystore.akt -- name
```
```
akt extract keystore.akt {name...}
```

This command allows to extract files or directories recursively from the
keystore.  It is possible to extract several files and directories
at the same time.

When the
*--* option is passed, the command accepts only one
argument.  It extracts the specified name and writes the result
on the standard output.  It can be used as a target for a pipe command.


### The genkey command
```
akt genkey [--remove] name
```

The
*genkey* command is used to generate or remove a password key file stored in some safe location
on the file system (see the
*keys* configuration variable).  The password key file can then be used with the
*--passkey* option.  It provides the same security level as using the
*--passfile* option but helps in setting up and using separate key files for different wallets.


### The mount command
```
akt mount keystore.akt [-f] [--enable-cache] mount-point
```

This command is available when the
**fuse**(8) support is enabled.  It allows to mount the keystore content on the
*mount-point* directory and access the encrypted content through the filesystem.
The
*akt* tool works as a daemon to serve
**fuse**(8) requests that come from the kernel.  The
*-f* option allows to run this daemon as a foreground process.
By default, the kernel cache are disabled because the keystore content
is decrypted and given as clear content to the kernel.  This could be
a security issue for some system and users.
The kernel cache can be enabled by using the
*--enable-cache* option.

To unmount the file system, one must use the
**mount**(8) command.
```
umount mount-point
```


### The set command
```
akt set keystore.akt name value
```

The
*set* command is used to store a content passed as command
line argument in the wallet.  If the wallet already contains
the name, the value is updated.


### The store command
```
akt store keystore.akt -- name
```
```
akt store keystore.akt {file...|directory...}
```

This command can store files or directories recursively in the
keystore.  It is possible to store several files and directories
at the same time.

When the
*--* option is passed, the command accepts only one
argument.  It reads the standard input and stores it under the
specified name.  It can be used as a target for a pipe command.


### The remove command
```
akt remove keystore.akt name ...
```

The
*remove* command is used to erase a content from the wallet.  The data block that contained
the content to protect is erased and replaced by zeros.
The secure key that protected the wallet entry is also cleared.
It is possible to remove several contents.


### The edit command
```
akt edit keystore.akt [-e editor] name
```

The
*edit* command can be used to edit the protected wallet entry by calling the
user's prefered editor with the content.  The content is saved in a
temporary directory and in a temporary file.  The editor is launched
with the path and when editing is finished the temporary file is read.
The temporary directory and files are erased when the editor terminates
successfully or not.  The editor can be specified by using the
*-e* option, by setting up the
*EDITOR* environment variable or by updating the
**editor**(1) alternative with
**update-alternative**(1). 

### The list command
```
akt list keystore.akt
```

The
*list* command describes the entries stored in the keystore with
their name, size, type, creation date and number of keys which
protect the entry.


### The get command
```
akt get keystore.akt [-n] name...
```

The
*get* command allows to retrieve the value associated with a wallet entry.
It retrieves the value for each name passed to the command.
The value is printed on the standard output.
By default a newline is emitted after each value.
The
*-n* option prevents the output of the trailing newline.


### The otp command
```
akt otp keystore.akt name

akt otp keystore.akt otpauth://totp/account?secret=secret&issuer=issuer
```

The
*otp* command manages OATH secrets and provides TOTP code
generation for a two factor authentication.  When an otpauth://totp/ string is given, the account
is extracted and it is inserted in the wallet.  When an account name
or issuer name is given, the command uses the secret to generate
the 6 digit codes for the authentication.  When no parameter are given
the command gives a list of known otpauth URI.


### The password-add command
```
akt password-add keystore.akt [--new-passfile file] [--new-password password] [--new-passenv name]
```

The
*password-add* command allows to add a new password in one of the wallet key slot.  Up to seven
passwords can be defined to protect the wallet.  The overall security of the wallet
is that of the weakest password.  To add a new password, one must know an existing
password.


### The password-remove command
```
akt password-remove keystore.akt [--force]
```

The
*password-remove* command can be used to erase a password from the wallet master key slots.
Removing the last password makes the keystore unusable and it is necessary
to pass the
*--force* option for that.


### The password-set command
```
akt password-set [--new-passfile file] [--new-password password] [--new-passenv name]
```

The
*password-set* command allows to change the current wallet password.

## SECURITY

Wallet master keys are protected by a derived key that is created from
the user's password using
*PBKDF2* and
*HMAC-256* as hashing operation.  When the wallet is first created, a random salt
and counter are allocated which are then used by the
*PBKDF2* generation.  The wallet can be protected by up to 7 different passwords.
Despite this, the security of the wallet master key still depends on the
strength of the user's password.  For this matter, it is still critical
for the security to use long passphrases.

The passphrase can be passed within an environment variable or within a
command line argument.  These two methods are considered unsafe because it
could be possible for other processes to see these values.  It is best to
use another method such as using the interactive form, passing the password
through a file or passing using a socket based communication.

When the wallet master key is protected using
**gpg2**(1) a 32-bytes random binary key and a 16-bytes random binary IV is created
to protect the wallet master key.  Another set of 80 bytes of random
binary data is used to encrypt and sign the whole wallet master key block.
The 128 bytes that form these random binary keys are encrypted using
the user's GPG public key and the result saved in the keystore header
block.  The
*--gpg* option is specified only for the creation of the keystore and allows
to encrypt a master key slot for several GPG keys.
To unlock the keystore file, the
**gpg2**(1) command will be used to decrypt the keystore header content automatically.
When the user's GPG private key is not found, it is not possible
to unlock the keystore with this method.

When several GPG keys are used to protect the wallet, they share the same
80 bytes to decrypt the wallet master key block but they have their own
key and IV to unlock the key slot.

Depending on the size, a data stored in the wallet is split in one or
several data entry. Each wallet data entry is then protected by their
own secret key and IV vector.
Wallet data entry are encrypted using AES-256-CBC.  The wallet data entry
key and IV vectors are protected by the wallet master key.

When the
*--split* option is used, the data storage files only contain the data blocks.
They do not contain any encryption key.  The data storage files use the
*.dkt* file extension.

## CONFIGURATION

The
*akt* global configuration file contains several configuration properties
which are used to customize several commands.  These properties can
be modified with the
*config* command.


### gpg-encrypt
This property defines the
**gpg2**(1) command to be used to encrypt a content.  The content to encrypt is
passed in the standard input and the encrypted content is read from
the standard output.  The GPG key parameter can be retrieved
by using the
*$USER* pattern.


### gpg-decrypt
This property defines the
**gpg2**(1) command to be used to decrypt a content.  The content to decrypt is
passed in the standard input and the decrypted content is read from
the standard output.


### gpg-list-keys
This property defines the
**gpg2**(1) command to be used to retrieve the list of available secret keys.
This command is executed when the keystore file is protected by a
GPG key to identify the possible GPG Key ids that
are capable of decrypting it.


### keys
This property defines the directory path where the key files generated by the
*genkey* and specified with the
*--passkey* option are stored.  The default location is the
*$HOME/.config/akt/keys* directory.


### fill-zero
This property controls whether
*akt* must fill unused data areas with zeros or with random bytes.

## SEE ALSO

**editor(1)**, **update-alternative(1)**, **ssh-askpass(1)**,
**gpg2(1)**, **mount(8)**, **fuse(8)**

## AUTHOR

Written by Stephane Carrez.

