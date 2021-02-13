### Directory Entries
The wallet repository block is encrypted with the wallet directory key.

```
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
| Entry type       | 2b   | = T_STRING, T_BINARY
| Name size        | 2b   |
| Name             | Nb   | DATA_NAME_ENTRY_SIZE + Name'Length
| Create date      | 8b   |
| Update date      | 8b   |
| Entry size       | 8b   v
+------------------+
| Entry ID         | 4b   ^
| Entry type       | 2b   | = T_WALLET
| Name size        | 2b   |
| Name             | Nb   | DATA_NAME_ENTRY_SIZE + Name'Length
| Create date      | 8b   |
| Update date      | 8b   |
| Wallet lid       | 4b   |
| Wallet master ID | 4b   v
+------------------+
| ...              |
+------------------+--
| 0 0 0 0          | 4b (End of name entry list = DATA_KEY_SEPARATOR)
+------------------+--
| ...              |     (random or zero)
+------------------+--  <- = Data key offset
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
+------------------+
| Block HMAC-256   | 32b
+------------------+--
```


