### Header block
The first block of the file is the keystore header block which contains clear
information signed by an HMAC header.  The header block contains the keystore
UUID as well as a short description of each storage data file.  It also contains
some optional header data.

```
+------------------+
| 41 64 61 00      | 4b = Ada
| 00 9A 72 57      | 4b = 10/12/1815
| 01 9D B1 AC      | 4b = 27/11/1852
| 00 01            | 2b = Version 1
| 00 01            | 2b = File header length in blocks
+------------------+
| Keystore UUID    | 16b
| Storage ID       | 4b
| Block size       | 4b
| Storage count    | 4b
| Header Data count| 2b
+------------------+-----
| Header Data size | 2b
| Header Data type | 2b = 0 (NONE), 1 (GPG1) 2, (GPG2)
+------------------+
| Header Data      | Nb
+------------------+-----
| ...              |
+------------------+-----
| 0                |
+------------------+-----
| ...              |
+------------------+-----
| Storage ID       | 4b
| Storage type     | 2b
| Storage status   | 2b  00 = open, Ada = sealed
| Storage max bloc | 4b
| Storage HMAC     | 32b = 44b
+------------------+----
| Header HMAC-256  | 32b
+------------------+----
```

