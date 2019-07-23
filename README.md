[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
# Bitcoin Wallet Library in Rust
This is a library to build Bitcoin wallets with Rust. 
It uses BIP32 key derivation, BIP39 mnemonics and BIP44 key 
hierarchy which makes it compatible to TREZOR, Ledger and many other
wallets.

## Goal
Offer a standalone wallet in conjunction with rust-bitcoin-spv.
I plan to add TREZOR and Ledger support.

## Status
This is work in progess, far from production quality. 
It aims to serve parallel development of an SPV client and a Lightning Node.

## Contributions and Vision
The goal is a library for key derivation, storage, serialization and account management.

Send in your PRs if aligned with above vision.