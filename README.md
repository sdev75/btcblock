## BTC Block file reader

Support for BTC .blk format.
It's supporting little endian system only at this time.
It has a built-in hex output enabled by default.
Some functions are not thread-safe by choice.

It can decode addresses in the following formats:

    P2PK (Pay-to-PubKey)
    P2PKH (Pay-to-PubKey-Hash)
    P2SH (Pay-To-Script-Hash)
    P2WPSH (Pay-To-Witness-Script-Hash)
    P2WPKH (Pay-to-Witness-PubKey-Hash)

### Preview

![Preview](genesis.png?raw=true "Genesis Block")

![Preview](preview.png?raw=true "Preview")

### Usage

```bash
clear; make -s && ./src/btcblock -d ~/.bitcoin/blocks
```
