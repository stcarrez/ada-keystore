### Data Block

Data block start is encrypted with wallet data key, data fragments are
encrypted with their own key.  Loading and saving data blocks occurs exclusively
from the workers package.  The data block can be stored in a separate file so that
the wallet repository and its keys are separate from the data blocks.

```
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
| Block HMAC-256   | 32b
+------------------+
```


