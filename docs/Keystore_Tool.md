# AKT Tool

## NAME

akt - Ada Keystore Tool

## SYNOPSIS

*akt* [ -v ] [-vv] [-V] [ -f
_file_ ] [ -d
_dir_ ] [ -p
_password_ ] [--password
_password_ ] [--passfile
_file_ ] [--passenv
_name_ ] [--passfd
_fd_ ] [--passask] [--passcmd
_cmd_ ]
_command_ 

## DESCRIPTION

_akt_ is a tool to store information in secure wallets
and protect the stored information by encrypting the content.
It is necessary to know one of the wallet password to access its content.
_akt_ can be used to safely store passwords, credentials,
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
_ssh-askpass_(1) external command,
* by running an external command,
* by asking interactively the user for the password,
* by asking through a network socket for the password.


## OPTIONS

The following options are recognized by _akt_:

-V
Prints the
_akt_ version.

-v
Enable the verbose mode.

-vv
Enable debugging output.

-f file

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
This method is safer.

--passfd fd

The keystore password is passed within a pipe whose file descriptor
number is given.  The file descriptor is read to obtain the password.
This method is safer.

--passask

The keystore password is retrieved by the running the external tool
_ssh-askpass_(1) which will ask the password through either KDE, Gnome or another
desktop interactive application.
The password is retrieved through a pipe that
_akt_ sets while launching the command.

--passcmd cmd

The keystore password is retrieved by the running the external command defined in
_cmd_. The command should print the password on its standard output without end of line.
The password is retrieved through a pipe that
_akt_ sets while launching the command.

## COMMANDS


### The create command
```
akt create [--counter-range min:max] [--split count] [--gpg user]
```

Create a new keystore and protect it with the password.

The password to protect the wallet is passed using one of the following options:
*--passfile* ,
*--passenv* ,
*--password* ,
*--passsocket* or
*--gpg*. When none of these options are passed, the password is asked interactively.

The
*--counter-range* option allows to control the range for the random counter used by PBKDF2
to generate the encryption key derived from the specified password.  High values
provide a strongest derived key at the expense of speed.

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
_gpg2_(1) command is used to encrypt that password and save it in the keystore
header.  The
_gpg2_(1) command is then used to decrypt that and be able to unlock the keystore.

### The set command
```
akt set name [value | -f file] 
```

The
_set_ command is used to store a content in the wallet.  The content is either
passed as argument or it can be read from a file by using the
_-f_ option.

### The store command
```
akt store name
```

The
_store_ command is intended to be used as a target for a pipe command.
It reads the standard input and stores the content which is read
in the wallet.

### The remove command
```
akt remove name ...
```

The
_remove_ command is used to erase a content from the wallet.  The data block that contained
the content to protect is erased and replaced by zeros.
The secure key that protected the wallet entry is also cleared.
It is possible to remove several contents.

### The edit command
```
akt edit [-e editor] name
```

The
_edit_ command can be used to edit the protected wallet entry by calling the
user's prefered editor with the content.  The content is saved in a
temporary directory and in a temporary file.  The editor is launched
with the path and when editing is finished the temporary file is read.
The temporary directory and files are erased when the editor terminates
successfully or not.  The editor can be specified by using the
_-e_ option, by setting up the
_EDITOR_ environment variable or by updating the
_editor_(1) alternative with
_update-alternative_(1). 
### The list command
```
akt list
```

The
_list_ command describes the entries stored in the wallet.

### The get command
```
akt get [-n] name...
```

The
_get_ command allows to retrieve the value associated with a wallet entry.
It retrieves the value for each name passed to the command.
By default a newline is emitted after each value.
The
_-n_ option prevents the output of the trailing newline.

### The password-add command
```
akt password-add [--new-passfile file] [--new-password password] [--new-passenv name]
```

The
_password-add_ command allows to add a new password in one of the wallet key slot.  Up to seven
passwords can be defined to protect the wallet.  The overall security of the wallet
is that of the weakest password.  To add a new password, one must know an existing
password.

### The password-remove command
```
akt password-remove [--force]
```

The
_password-remove_ command can be used to erase a password from the wallet master key slots.
Removing the last password makes the keystore unusable and it is necessary
to pass the
_--force_ option for that.

### The password-set command
```
akt password-set [--new-passfile file] [--new-password password] [--new-passenv name]
```

The
_password-set_ command allows to change the current wallet password.

## SECURITY

Wallet master keys are protected by a derived key that is created from the user's
password using
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
_gpg2_(1) a 256-bytes random binary string is created to protect the wallet master
key.  This random binary string is then encrypted using the user's

*--gpg* option is specified only for the creation of the keystore.
To unlock the keystore file, the
_gpg2_(1) command will be used to decrypt the keystore header content automatically.
When the user's GPG private key is not found, it is not possible
to unlock the keystore with this method.

Depending on the size, a data stored in the wallet is split in one or
several data entry. Each wallet data entry is then protected by their
own secret key and IV vector.
Wallet data entry are encrypted using AES-256-CBC.  The wallet data entry
key and IV vectors are protected by the wallet master key.

When the
*--split* option is used, the data storage files only contain the data blocks.
They do not contain any encryption key.  The data storage files use the
*.dkt* file extension.

## SEE ALSO

_editor(1)_, _update-alternative(1)_, _ssh-askpass(1)_,
_gpg2(1)_

## AUTHOR

Written by Stephane Carrez.

