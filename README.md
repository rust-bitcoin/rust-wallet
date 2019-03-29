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

## Basic Usage
Install `docker`, `docker-compose` and `rustup`.

Optionally install `electrumx`. Run in some `tmp` directory:
```
git clone https://github.com/romanz/electrs
cd electrs
git checkout e49cef1bbcaf1710613dab4578d61b99c7dbd478
cargo install --debug --path .
```

Launch `electrumx`:

```
electrs --network=regtest --jsonrpc-import --cookie=user:password --daemon-rpc-addr=127.0.0.1:18332
```

Install the wallet:
```
git clone https://github.com/LightningPeach/rust-wallet.git
cd rust-wallet/rust-wallet-grpc
cargo install --debug --path .
```

If the wallet already installed the last command should be: 

```
cargo install --debug --force --path .
```

in order to rewrite the binary.

Launch the wallet:
```
docker-compose up
wallet
```

It is possible to run `wallet` with `electrumx`:
```
wallet --electrumx
```
 
See `wallet --help` for more information.

Generate some money to bitcoind and send to the wallet

```
docker exec -ti rust-wallet_bitcoind_1 sh
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password generate 110
wallet-cli newaddress
bcrt1q3fnf5dll9cjuqxgw6l2nkez4mu6ktmn83ahd3q
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password sendtoaddress bcrt1q3fnf5dll9cjuqxgw6l2nkez4mu6ktmn83ahd3q 1
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password generate 1
wallet-cli sync_with_tip
wallet-cli walletbalance
100000000
```
Send money back to the bitcoind
```
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password getnewaddress --address_type bech32
bcrt1qku9u0rtxy5t9uxnyp2nqt9z33ffxy6qhjlcz49
wallet-cli send_coins --dest_addr bcrt1qku9u0rtxy5t9uxnyp2nqt9z33ffxy6qhjlcz49 --amt 50000000 --submit
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password generate 1
wallet-cli sync_with_tip
wallet-cli walletbalance
49990000
```

## Contributions and Vision
The goal is a library for key derivation, storage, serialization and account management.

Send in your PRs if aligned with above vision.
