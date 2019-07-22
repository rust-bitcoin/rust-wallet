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
//! # Account derivation
//!
//! TREZOR compatible account derivation (BIP44)
//!

use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ExtendedPubKey, ExtendedPrivKey,ChildNumber};
use context::{SecpContext, MasterKeyEntropy, Seed};
use error::WalletError;
use mnemonic::Mnemonic;
use account::{Account,AccountAddressType};
use std::sync::Arc;
use std::time::SystemTime;
use std::collections::HashMap;

// a factory for TREZOR (BIP44) compatible accounts
pub struct MasterAccount {
    master_key: ExtendedPrivKey,
    encrypted: Vec<u8>,
    context: Arc<SecpContext>,
    network: Network,
    accounts: HashMap<AccountAddressType, Vec<Account>>
}

impl MasterAccount {
    /// initialize with new random master key
    pub fn new (entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str) -> Result<MasterAccount, WalletError> {
        let context = SecpContext::new();
        let (master_key, _, encrypted) = context.new_master_private_key (entropy, network, passphrase, salt)?;
        Ok(MasterAccount { context: Arc::new(context), master_key, encrypted, network, accounts: HashMap::new()})
    }

    /// decrypt stored master key
    pub fn decrypt (encrypted: &[u8], network: Network, passphrase: &str, salt: &str, births: HashMap<AccountAddressType, Vec<u64>>) -> Result<MasterAccount, WalletError> {
        let mnemonic = Mnemonic::new (encrypted, passphrase)?;
        let context = Arc::new(SecpContext::new());
        let master_key = context.master_private_key(network, &Seed::new(&mnemonic, salt))?;
        let mut accounts = HashMap::new();
        for (a, births) in births.iter() {
            for (i, b) in births.iter().enumerate() {
                accounts.entry(*a).or_insert(Vec::new()).push(
                Self::new_account(context.clone(), &master_key, i as u32, *a, *b)?);
            }
        }
        Ok(MasterAccount { context, master_key, encrypted: encrypted.to_vec(), network, accounts})
    }

    /// only this should be stored (encrypted, account births, network)
    pub fn configuration (&self) -> (Vec<u8>, HashMap<AccountAddressType, Vec<u64>>, Network) {
        (self.encrypted.clone(),
            self.accounts.iter().map(|(a, v)|
            (*a, v.iter().map(|c| c.birth()).collect::<Vec<_>>())).collect::<HashMap<_,_>>(), self.network)
    }

    /// get a copy of the master public key
    pub fn master_public (&self) ->ExtendedPubKey {
        self.context.extended_public_from_private(&self.master_key)
    }

    pub fn add_account(&mut self, address_type: AccountAddressType) -> Result<usize, WalletError> {
        let accounts = self.accounts.entry(address_type).or_insert(Vec::new());
        let account = Self::new_account(self.context.clone(), &self.master_key, accounts.len() as u32, address_type,
                                        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())?;
        accounts.push(account);
        Ok(accounts.len())
    }

    pub fn number_of_accounts(&self, address_type: AccountAddressType) -> usize {
        if let Some(v) = self.accounts.get(&address_type) {
            v.len()
        }
        else {
            0
        }
    }

    pub fn get_account (&self, address_type: AccountAddressType, index: usize) -> Option<&Account> {
        if let Some(v) = self.accounts.get(&address_type) {
            v.get(index)
        }
        else {
            None
        }
    }

    pub fn get_account_mut (&mut self, address_type: AccountAddressType, index: usize) -> Option<&mut Account> {
        if let Some(v) = self.accounts.get_mut(&address_type) {
            v.get_mut(index)
        }
        else {
            None
        }
    }

    /// create an account
    fn new_account (context: Arc<SecpContext>, master_key: &ExtendedPrivKey, account_number: u32, address_type: AccountAddressType, birth: u64) -> Result<Account, WalletError> {
        let mut key = match address_type {
            AccountAddressType::P2PKH => context.private_child(&master_key, ChildNumber::Hardened { index: 44 })?,
            AccountAddressType::P2SHWH => context.private_child(&master_key, ChildNumber::Hardened { index: 49 })?
        };
        key = match key.network {
            Network::Bitcoin => context.private_child(&key, ChildNumber::Hardened { index: 0 })?,
            Network::Testnet => context.private_child(&key, ChildNumber::Hardened { index: 1 })?,
            Network::Regtest => context.private_child(&key, ChildNumber::Hardened { index: 1 })?
        };
        key = context.private_child(&key, ChildNumber::Hardened { index: account_number })?;
        Account::new(context.clone(), key, address_type, birth, key.network)
    }
}
