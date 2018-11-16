use bitcoin::{
    util::hash::Sha256dHash,
    Block, Transaction, OutPoint,
};
use account::{Account, AccountAddressType, Utxo};
use accountfactory::LockId;

use std::error::Error;

pub trait Wallet {
    fn get_account(&self, address_type: AccountAddressType) -> &Account;
    fn get_account_mut(&mut self, address_type: AccountAddressType) -> &mut Account;
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
    // TODO(evg): add new address method??
}

//pub trait Account {
//    fn new_address(&mut self) -> Result<String, Box<Error>>;
//    fn new_change_address(&mut self) -> Result<String, Box<Error>>;
//}

pub trait BlockChainIO {
    fn get_block_count(&self) -> u32;
    fn get_block_hash(&self, height: u32) -> Sha256dHash;
    fn get_block(&self, header_hash: &Sha256dHash) -> Block;
    fn send_raw_transaction(&self, tx: &Transaction);
}