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
use bitcoin::{
    util::hash::Sha256dHash,
    Block, Transaction, OutPoint,
};
use account::{Account, AccountAddressType, Utxo};
use accountfactory::LockId;

use std::error::Error;

pub trait Wallet {
    fn new_address(&mut self, address_type: AccountAddressType) -> Result<String, Box<Error>>;
    fn new_change_address(&mut self, address_type: AccountAddressType) -> Result<String, Box<Error>>;
    fn get_utxo_list(&self) -> Vec<Utxo>;
    fn wallet_balance(&self) -> u64;
    fn unlock_coins(&mut self, lock_id: LockId);
    fn send_coins(
        &mut self,
        addr_str: String,
        amt: u64,
        submit: bool,
        lock_coins: bool,
        witness_only: bool,
    ) -> Result<(Transaction, LockId), Box<Error>>;
    fn make_tx(
        &mut self,
        ops: Vec<OutPoint>,
        addr_str: String,
        amt: u64,
        submit: bool,
    ) -> Result<Transaction, Box<Error>>;
    fn publish_tx(&self, tx: &Transaction);
    fn sync_with_tip(&mut self);
}

pub trait BlockChainIO {
    fn get_block_count(&self) -> u32;
    fn get_block_hash(&self, height: u32) -> Sha256dHash;
    fn get_block(&self, header_hash: &Sha256dHash) -> Block;
    fn send_raw_transaction(&self, tx: &Transaction);
}