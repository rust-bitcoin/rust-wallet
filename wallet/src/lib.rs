//
// Copyright 2018 rust-wallet developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
extern crate crypto;
extern crate secp256k1;
extern crate bitcoin;
extern crate rand;
extern crate hex;
// extern crate bitcoin_rpc_client;
extern crate bitcoin_bech32;
extern crate rocksdb;
extern crate byteorder;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate log;
extern crate simple_logger;
extern crate electrumx_client;

pub mod mnemonic;
pub mod error;
pub mod keyfactory;
pub mod walletlibrary;
pub mod default;
pub mod electrumx;
pub mod account;
mod db;
pub mod interface;