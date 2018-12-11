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
Install the wallet

```
git clone https://github.com/LightningPeach/rust-wallet.git
cd rust-wallet/rust-wallet-grpc
cargo install --debug
```

Launch the wallet
```
docker-compose up
wallet
```
Generate some money to bitcoind and send to the wallet

```
docker exec -ti rust-wallet_bitcoind_1 sh
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password generate 110
client newaddress
bcrt1q3fnf5dll9cjuqxgw6l2nkez4mu6ktmn83ahd3q
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password sendtoaddress bcrt1q3fnf5dll9cjuqxgw6l2nkez4mu6ktmn83ahd3q 1
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password generate 1
client sync_with_tip
client walletbalance
100000000
```
Send money back to the bitcoind
```
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password getnewaddress --address_type bech32
bcrt1qku9u0rtxy5t9uxnyp2nqt9z33ffxy6qhjlcz49
client send_coins --dest_addr bcrt1qku9u0rtxy5t9uxnyp2nqt9z33ffxy6qhjlcz49 --amt 50000000 --submit
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password generate 1
client sync_with_tip
client walletbalance
49990000
```

## Contributions and Vision
The goal is a library for key derivation, storage, serialization and account management.

Send in your PRs if aligned with above vision.
