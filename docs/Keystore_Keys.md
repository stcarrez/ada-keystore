### Master keys
Wallet header encrypted with the parent wallet id

```
+------------------+
| 01 01            | 2b
| Encrypt size     | 2b
| Parent Wallet id | 4b
| PAD 0            | 4b
| PAD 0            | 4b
+------------------+
| Wallet magic     | 4b
| Wallet version   | 4b
| Wallet lid       | 4b
| Wallet block ID  | 4b
+------------------+
| Wallet gid       | 16b
+------------------+
| Wallet key count | 4b
| PAD 0            | 4b
+------------------+
| Key type         | 4b
| Key size         | 4b
| Counter for key  | 4b
| Counter for iv   | 4b
| Salt for key     | 32b
| Salt for iv      | 32b
| Key slot sign    | 32b
| Dir key # 1      | 32b ---
| Dir iv # 1       | 16b  ^
| Dir sign # 1     | 32b  |
| Data key # 1     | 32b  |
| Data iv # 1      | 16b  | Encrypted by user's password
| Data sign #1     | 32b  |
| Key key # 1      | 32b  |
| Key iv # 1       | 16b  v
| Key sign #1      | 32b ---
| Slot HMAC-256    | 32b
| PAD 0 / Random   | 80b
+------------------+
| Key slot #2      | 512b
+------------------+
| Key slot #3      | 512b
+------------------+
| Key slot #4      | 512b
+------------------+
| Key slot #5      | 512b
+------------------+
| Key slot #6      | 512b
+------------------+
| Key slot #7      | 512b
+------------------+
| PAD 0 / Random   |
+------------------+
| Block HMAC-256   | 32b
+------------------+
```


