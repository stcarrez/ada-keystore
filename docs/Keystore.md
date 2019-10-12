## Keystore
The `Keystore` package provides operations to store information in secure wallets and
protect the stored information by encrypting the content.  It is necessary to know one
of the wallet password to access its content.  Wallets are protected by a master key
using AES-256 and the wallet master key is protected by a user password.  The wallet
defines up to 7 slots that identify a password key that is able to unlock the master key.
To open a wallet, it is necessary to unlock one of the 7 slots by providing the correct
password.  Wallet key slots are protected by the user's password and the PBKDF2-HMAC-256
algorithm, a random salt, a random counter and they are encrypted using AES-256.

### Creation
To create a keystore you will first declare a `Wallet_File` instance.  You will also need
a password that will be used to protect the wallet master key.

```Ada
with Keystore.Files;
...
  WS   : Keystore.Files.Wallet_File;
  Pass : Keystore.Secret := Keystore.Create ("There was no choice but to be pioneers");
```

You can then create the keystore file by using the `Create` operation:

```Ada
  WS.Create ("secure.akt", Pass);
```

### Storing
Values stored in the wallet are protected by their own encryption keys using AES-256.
The encryption key is generated when the value is added to the wallet by using the `Add`
operation.

```Ada
  WS.Add ("Grace Hopper", "If it's a good idea, go ahead and do it.");
```

The `Get` function allows to retrieve the value.  The value is decrypted only when the `Get`
operation is called.

```Ada
  Citation : constant String := WS.Get ("Grace Hopper");
```

The `Delete` procedure can be used to remove the value.  When the value is removed,
the encryption key and the data are erased.

```Ada
  WS.Delete ("Grace Hopper");
```

