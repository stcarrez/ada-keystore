
## NAME

akt - Ada Keystore Tool

## SYNOPSIS

*akt* [ -v ] [-d] [ -f
_file_ ] [ -p
_password_ ] [--password
_password_ ] [--passfile
_file_ ] [--passenv
_name_ ] [--passfd
_fd_ ]
_command_ 

## DESCRIPTION

_akt_ is a tool to store information in secure wallets
and protect the stored information by encrypting the content.
It is necessary to know one of the wallet password to access its content.
_akt_ can be used to safely store passwords, credentials,
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
signed using HMAC-256.  Large values can be written to several data
blocks and in that case each fragment is encrypted by using its own
encryption key.

The tool provides several commands that allow to create a keystore,
insert values, retrieve values or delete them.  You can use it to
store your passwords, your secret keys and even your documents.

Passwords are retrieved using one of the following options:
.IP \(bu 4
by reading a file that contains the password,
.IP \(bu 4
by looking at an environment variable,
.IP \(bu 4
by using a command line argument,
.IP \(bu 4
by asking interactively the user for the password,
.IP \(bu 4
by asking through a network socket for the password.


## OPTIONS

The following options are recognized by _akt_:

-v
Prints the
_akt_ version.

-d
Enable debugging output.

-f file

Specifies the path of the keystore file to open.

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

## COMMANDS


### The create command
```
akt create [--passfile {path}] [--passenv {name}]
```

Create a new keystore and protect it with the password.

The password to protect the wallet is passed using one of the following options:
*--passfile* ,
*--passenv* ,
*--password* ,
*--passsocket* .  When none of these options are passed, the password is asked interactively.

### The set command
```
akt set name [value | -f file] 
```

The
_set_ command is used to store a content in the wallet.  The content is either
passed as argument or it can be read from a file by using the
_-f_ option.

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

## SECURITY

Wallet master keys are protected by a derived key that is created from the user's
password using
*PBKDF2* and
*HMAC-512* as hashing operation.  When the wallet is first created, a random salt
and counter are allocated which are then used by the
*PBKDF2* generation.  The wallet can be protected by up to 8 different passwords.
Despite this, the security of the wallet master key still depends on the
strength of the user's password.  For this matter, it is still critical
for the security to use long passphrases.

The passphrase can be passed within an environment variable or within a
command line argument.  These two methods are considered unsafe because it
could be possible for other processes to see these values.  It is best to
use another method such as using the interactive form, passing the password
through a file or passing using a socket based communication.

Each wallet data entry is protected by using its own secret key and IV vector.
Wallet data are encrypted using AES-256-CBC.  The wallet data entry key and IV
vectors are protected by the wallet master key.

## SEE ALSO

_editor(1)_, _update-alternative(1)_

## AUTHOR

Written by Stephane Carrez.

