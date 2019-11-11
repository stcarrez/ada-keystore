# Implementation

## File layouts

The data is organized in blocks of 4K.  The first block is a header
block used to store various information to identify the storage files.
Other blocks have a clear 16-byte header and an HMAC-256 signature
at the end.  Blocks are encrypted either by using the master key,
the directory key, the data key or a per-data fragment key.

![Keystore blocks overview](images/akt-keystore-blocks.png)

