[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
# Bitcoin Wallet Library in Rust
This is a library to build Bitcoin wallets with Rust. 
It uses BIP32 key derivation, BIP39 mnemonics and BIP44, BIP48, BIP84 key 
hierarchy which makes it compatible to TREZOR, Ledger and many other
wallets.

It supports legacy P2PKH, transitional P2SHWPKH and native segwit P2WPKH for single key signatures
and native P2WSH for arbitrary sripts.

