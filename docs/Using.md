# Using Ada Keystore Tool

The `akt` tool is the command line tool that manages the wallet.
It provides the following commands:

* `create`:   create the keystore
* `edit`:     edit the value with an external editor
* `get`:      get a value from the keystore
* `help`:     print some help
* `list`:     list values of the keystore
* `remove`:   remove values from the keystore
* `set`:     insert or update a value in the keystore

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

You can also use the `akt` command together with the `tar` command
to create secure backups.  You can create the compressed tar file,
pipe the result to the `akt` command to store the content in the wallet.

```
   tar czf - dir-to-backup | akt store secure.akt -- backup.tar.gz
```

To extract the backup you can use the `extract` command and feed the
result to the `tar` command as follows:

```
   akt extract secure.akt -- backup.tar.gz | tar xzf -
```

