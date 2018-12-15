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
use walletlibrary::LockId;

use std::error::Error;

pub trait Wallet {
    fn wallet_lib(&self) -> &Box<WalletLibraryInterface + Send>;
    fn wallet_lib_mut(&mut self) -> &mut Box<WalletLibraryInterface + Send>;
    fn reconnect(&mut self);
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
    fn publish_tx(&mut self, tx: &Transaction);
    fn sync_with_tip(&mut self);
}

pub trait WalletLibraryInterface {
    fn new_address(&mut self, address_type: AccountAddressType) -> Result<String, Box<Error>>;
    fn new_change_address(&mut self, address_type: AccountAddressType) -> Result<String, Box<Error>>;
    fn get_utxo_list(&self) -> Vec<Utxo>;
    fn wallet_balance(&self) -> u64;
    fn unlock_coins(&mut self, lock_id: LockId);
    fn send_coins(
        &mut self,
        addr_str: String,
        amt: u64,
        lock_coins: bool,
        witness_only: bool,
    ) -> Result<(Transaction, LockId), Box<Error>>;
    fn make_tx(
        &mut self,
        ops: Vec<OutPoint>,
        addr_str: String,
        amt: u64,
    ) -> Result<Transaction, Box<Error>>;
    fn get_account_mut(&mut self, address_type: AccountAddressType) -> &mut Account;
    fn get_last_seen_block_height_from_memory(&self) -> usize;
    fn update_last_seen_block_height_in_memory(&mut self, block_height: usize);
    fn update_last_seen_block_height_in_db(&mut self, block_height: usize);
    fn get_full_address_list(&self) -> Vec<String>;
    fn process_tx(&mut self, tx: &Transaction);
}

pub trait BlockChainIO {
    fn get_block_count(&self) -> u32;
    fn get_block_hash(&self, height: u32) -> Sha256dHash;
    fn get_block(&self, header_hash: &Sha256dHash) -> Block;
    fn send_raw_transaction(&self, tx: &Transaction);
}