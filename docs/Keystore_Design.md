# Implementation

## File layouts
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
| Header HMAC-256  | 32b
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
```

### Directory Entries
The wallet repository block is encrypted with the wallet directory key.

```
+------------------+
| Block HMAC-256   | 32b
+------------------+
| 02 02            | 2b
| Encrypt size     | 2b = BT_DATA_LENGTH
| Wallet id        | 4b
| PAD 0            | 4b
| PAD 0            | 4b
+------------------+
| Next block ID    | 4b  Block number for next repository block with same storage
| Data key offset  | 2b  Starts at IO.Block_Index'Last, decreasing
+------------------+
| Entry ID         | 4b   ^
| Entry type       | 2b   |
| Name size        | 2b   |
| Name             | Nb   | DATA_NAME_ENTRY_SIZE + Name'Length
| Create date      | 8b   |
| Update date      | 8b   |
| Entry size       | 8b   v
+------------------+
| ...              |
+------------------+--
| 0 0 0 0          | 16b (End of name entry list)
+------------------+--
| ...              |     (random or zero)
+------------------+--
| 0 0 0 0          | 16b (End of data key list)
+------------------+--
| ...              |
+------------------+
| Storage ID       | 4b   ^ Repeats "Data key count" times
| Data block ID    | 4b   |
| Data size        | 2b   | DATA_KEY_ENTRY_SIZE = 58b
| Content IV       | 16b  |
| Content key      | 32b  v
+------------------+
| Entry ID         | 4b   ^
| Data key count   | 2b   | DATA_KEY_HEADER_SIZE = 10b
| Data offset      | 4b   v
+------------------+--
```


### Data Block

Data block start is encrypted with wallet data key, data fragments are
encrypted with their own key.  Loading and saving data blocks occurs exclusively
from the workers package.  The data block can be stored in a separate file so that
the wallet repository and its keys are separate from the data blocks.

```
+------------------+
| Block HMAC-256   | 32b
+------------------+
| 03 03            | 2b
| Encrypt size     | 2b = DATA_ENTRY_SIZE * Nb data fragment
| Wallet id        | 4b
| PAD 0            | 4b
| PAD 0            | 4b
+------------------+-----
| Entry ID         | 4b  Encrypted with wallet id
| Slot size        | 2b
| 0 0              | 2b
| Data offset      | 8b
| Content HMAC-256 | 32b => 48b = DATA_ENTRY_SIZE
+------------------+
| ...              |
+------------------+-----
| ...              |
+------------------+
| Data content     |     Encrypted with data entry key
+------------------+-----
```


