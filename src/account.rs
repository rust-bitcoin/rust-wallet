//
// Copyright 2018 Tamas Blummer
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
//!
//! # Accounts
//!
//! TREZOR compatible accounts (BIP44, BIP49, BIP84)
//!
use bitcoin::{
    Address, Transaction, PrivateKey, Script,
    blockdata::transaction::SigHashType,
    util::bip32::{ExtendedPrivKey,ChildNumber},
    network::constants::Network
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use context::SecpContext;
use error::WalletError;

/// Address type an account is using
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum AccountAddressType {
    /// legacy pay to public key hash
    P2PKH,
    /// transitional segwit pay to public key hash in legacy format
    P2SHWPKH,
    /// native segwit pay to public key hash in bech format
    P2WPKH,
}

/// a TREZOR compatible account
pub struct Account {
    address_type: AccountAddressType,
    key: ExtendedPrivKey,
    context: Arc<SecpContext>,
    birth: u64, // seconds in unix epoch
    network: Network,
    pub receive: SubAccount,
    pub change: SubAccount
}

impl Account {
    pub fn new (context: Arc<SecpContext>, key: ExtendedPrivKey, address_type: AccountAddressType, birth: Option<u64>, network: Network) -> Result<Account, WalletError> {
        let birth = birth.unwrap_or(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

        let receive = SubAccount{
            context: context.clone(), address_type, birth, next:0,
            key: context.private_child(&key, ChildNumber::Normal{index:0})?,
            network
        };
        let change = SubAccount{
            context: context.clone(), address_type, birth, next:0,
            key: context.private_child(&key, ChildNumber::Normal{index:1})?,
            network
        };

        Ok(Account { context, key: key, address_type, birth, receive, change, network })
    }

    pub fn birth (&self) -> u64 {
        self.birth
    }
}

pub struct SubAccount {
    address_type: AccountAddressType,
    context: Arc<SecpContext>,
    key: ExtendedPrivKey,
    birth: u64,
    network: Network,
    next: u32
}

impl SubAccount {
    // get private key for an index
    pub fn get_key(&self, ix: u32) -> Result<PrivateKey,WalletError> {
        Ok(self.context.private_child(&self.key, ChildNumber::Normal {index: ix})?.private_key)
    }

    // get the address for an index
    pub fn get_address (&self, ix: u32) -> Result<Address,WalletError> {
        match self.get_key(ix) {
            Ok(pk) => {
                let address = match self.address_type {
                    AccountAddressType::P2PKH => Address::p2pkh(&self.context.public_from_private(&pk), self.network),
                    AccountAddressType::P2SHWPKH => Address::p2shwpkh(&self.context.public_from_private(&pk), self.network),
                    AccountAddressType::P2WPKH => Address::p2wpkh(&self.context.public_from_private(&pk), self.network),
                };
                Ok(address)
            },
            Err(e) => Err(e)
        }
    }

    pub fn iter_addresses(&self, from: u32) -> AddressIterator {
        AddressIterator::new(self, from)
    }
}

pub struct AddressIterator<'a> {
    account: &'a SubAccount,
    from : u32,
}

impl<'a> AddressIterator<'a> {
    pub fn new (account: &'a SubAccount, from: u32) -> AddressIterator<'a> {
        AddressIterator{from, account}
    }
}

impl<'a> Iterator for AddressIterator<'a> {
    type Item = Result<Address, WalletError>;

    fn next(&mut self) -> Option<Self::Item> {
        let ix = self.from;
        self.from += 1;
        Some(self.account.get_address(ix))
    }
}

pub fn sign_pkh (transaction: &Transaction, ix: usize, script: &Script, hash_type: SigHashType, key: &PrivateKey, ctx: Arc<SecpContext>) -> Result<Vec<u8>, WalletError> {
    let sighash = transaction.signature_hash(ix, script, hash_type.as_u32());
    let mut signature = ctx.sign(&sighash[..], key)?.serialize_der();
    signature.push(hash_type.as_u32() as u8);
    Ok(signature)
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::blockdata::transaction::{TxOut, TxIn, OutPoint};
    use bitcoin::blockdata::script::Builder;
    use bitcoin_hashes::sha256d;
    use context::MasterKeyEntropy;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::io::Cursor;

    #[test]
    fn test_pkh () {

        let ctx = Arc::new(SecpContext::new());
        let (master, _, _) = ctx.new_master_private_key(MasterKeyEntropy::Low, Network::Bitcoin, "", "").unwrap();
        let account = Account::new(ctx.clone(), master, AccountAddressType::P2PKH, None, Network::Bitcoin).unwrap();
        let pk = account.receive.get_key(0).unwrap();
        let source = account.receive.get_address(0).unwrap();
        let target = account.receive.get_address(1).unwrap();

        let input_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid: sha256d::Hash::default(), vout: 0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0xffffffff,
            version: 2
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid, vout:0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0xffffffff,
            version: 2
        };

        let mut spent = HashMap::new();
        spent.insert(input_transaction.txid(), input_transaction.clone());

        let signature = sign_pkh(&spending_transaction, 0, &source.script_pubkey(), SigHashType::All, &pk, ctx.clone()).unwrap();

       let public = ctx.public_from_private(&pk);

        spending_transaction.input[0].script_sig = Builder::new()
            .push_slice(signature.as_slice())
            .push_slice(public.to_bytes().as_slice()).into_script();
        spending_transaction.verify(&spent).unwrap();
    }
}