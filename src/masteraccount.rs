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
use bitcoin::Script;
use context::{SecpContext, MasterKeyEntropy, Seed};
use error::WalletError;
use mnemonic::Mnemonic;
use account::{Account,AccountAddressType};
use std::sync::Arc;

// a factory for TREZOR (BIP44) compatible accounts
pub struct MasterAccount {
    master_key: ExtendedPrivKey,
    encrypted: Vec<u8>,
    context: Arc<SecpContext>,
    accounts: Vec<Account>,
    network: Network
}

impl MasterAccount {
    /// initialize with new random master key
    pub fn new (entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str) -> Result<MasterAccount, WalletError> {
        let context = SecpContext::new();
        let (master_key, _, encrypted) = context.new_master_private_key (entropy, network, passphrase, salt)?;
        Ok(MasterAccount { context: Arc::new(context), master_key, encrypted, accounts: Vec::new(), network})
    }

    /// decrypt stored master key
    pub fn decrypt (encrypted: &[u8], network: Network, passphrase: &str, salt: &str, births: Vec<(AccountAddressType, u64, Vec<u32>)>, look_ahead: u32) -> Result<MasterAccount, WalletError> {
        let mnemonic = Mnemonic::new (encrypted, passphrase)?;
        let context = Arc::new(SecpContext::new());
        let master_key = context.master_private_key(network, &Seed::new(&mnemonic, salt))?;
        let mut accounts = Vec::new();
        for (i, (at, birth, subs)) in births.iter().enumerate() {
            let account = Self::new_account(context.clone(), &master_key, i as u32, *at, Some(*birth), subs.clone(), look_ahead)?;
            accounts.push(account);
        }
        Ok(MasterAccount { context, master_key, encrypted: encrypted.to_vec(), accounts, network})
    }

    /// get a copy of the master public key
    pub fn master_public (&self) ->ExtendedPubKey {
        self.context.extended_public_from_private(&self.master_key)
    }

    pub fn add_account(&mut self, address_type: AccountAddressType, nsubs: u32, look_ahead: u32) -> Result<u32, WalletError> {
        let len = self.accounts.len() as u32;
        let account = Self::new_account(self.context.clone(), &self.master_key, len, address_type, None, vec!(0u32;nsubs as usize), look_ahead)?;
        self.accounts.push(account);
        Ok(len)
    }

    pub fn iter(&self) -> impl Iterator<Item=&Account> {
        self.accounts.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item=&mut Account> {
        self.accounts.iter_mut()
    }

    pub fn get(&self, account: u32) -> Option<&Account> {
        self.accounts.get(account as usize)
    }

    pub fn get_mut(&mut self, account: u32) -> Option<&mut Account> {
        self.accounts.get_mut(account as usize)
    }

    pub fn get_scripts<'a>(&'a self) -> impl Iterator<Item=(u32, u32, u32, Script)> + 'a {
        self.accounts.iter().enumerate().flat_map(|(i, a)| a.get_scripts().map(move |(a, sa, s)| (i as u32, a, sa, s)))
    }

    /// create an account
    fn new_account (context: Arc<SecpContext>, master_key: &ExtendedPrivKey, account_number: u32, address_type: AccountAddressType, birth: Option<u64>, used: Vec<u32>, look_ahead: u32) -> Result<Account, WalletError> {
        let mut key = match address_type {
            AccountAddressType::P2PKH => context.private_child(&master_key, ChildNumber::Hardened { index: 44 })?,
            AccountAddressType::P2SHWPKH => context.private_child(&master_key, ChildNumber::Hardened { index: 49 })?,
            AccountAddressType::P2WPKH => context.private_child(&master_key, ChildNumber::Hardened { index: 84 })?,
            AccountAddressType::P2WSH(index) => context.private_child(&master_key, ChildNumber::Hardened { index })?
        };
        key = match key.network {
            Network::Bitcoin => context.private_child(&key, ChildNumber::Hardened { index: 0 })?,
            Network::Testnet => context.private_child(&key, ChildNumber::Hardened { index: 1 })?,
            Network::Regtest => context.private_child(&key, ChildNumber::Hardened { index: 1 })?
        };
        key = context.private_child(&key, ChildNumber::Hardened { index: account_number })?;
        Account::new(context.clone(), key, address_type, birth, used, look_ahead, key.network )
    }
}
