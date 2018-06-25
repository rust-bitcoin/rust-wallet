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
use keyfactory::{KeyFactory, MasterKeyEntropy, Seed};
use error::WalletError;
use mnemonic::Mnemonic;
use account::{Account,AccountAddressType};
use std::sync::Arc;

// a factory for TREZOR (BIP44) compatible accounts
pub struct AccountFactory {
    master_key: ExtendedPrivKey,
    mnemonic: Mnemonic,
    encrypted: Vec<u8>,
    key_factory: Arc<KeyFactory>
}

impl AccountFactory {
    /// initialize with new random master key
    pub fn new (entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str) -> Result<AccountFactory, WalletError> {
        let key_factory = KeyFactory::new();
        let (master_key, mnemonic, encrypted) = key_factory.new_master_private_key (entropy, network, passphrase, salt)?;
        Ok(AccountFactory{key_factory: Arc::new(key_factory), master_key, mnemonic, encrypted})
    }

    /// decrypt stored master key
    pub fn decrypt (encrypted: &[u8], network: Network, passphrase: &str, salt: &str) -> Result<AccountFactory, WalletError> {
        let mnemonic = Mnemonic::new (encrypted, passphrase)?;
        let key_factory = KeyFactory::new();
        let master_key = key_factory.master_private_key(network, &Seed::new(&mnemonic, salt))?;
        Ok(AccountFactory{key_factory: Arc::new(key_factory), master_key, mnemonic, encrypted: encrypted.to_vec()})
    }

    /// get a copy of the master private key
    pub fn master_private (&self) -> ExtendedPrivKey {
        self.master_key.clone()
    }

    /// get a copy of the master public key
    pub fn master_public (&self) ->ExtendedPubKey {
        self.key_factory.extended_public_from_private(&self.master_key)
    }

    pub fn mnemonic (&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn encrypted (&self) -> Vec<u8> {
        self.encrypted.clone()
    }

    /// get an account
    pub fn account (&self, account_number: u32, address_type: AccountAddressType) -> Result<Account, WalletError> {
        let mut key = match address_type {
            AccountAddressType::P2PKH => self.key_factory.private_child(&self.master_key, ChildNumber::Hardened(44))?,
            AccountAddressType::P2SHWH => self.key_factory.private_child(&self.master_key, ChildNumber::Hardened(49))?
        };
        key = match key.network {
            Network::Bitcoin => self.key_factory.private_child(&key, ChildNumber::Hardened(0))?,
            Network::Testnet => self.key_factory.private_child(&key, ChildNumber::Hardened(1))?
        };
        key = self.key_factory.private_child(&key, ChildNumber::Hardened(account_number))?;
        Ok(Account::new(self.key_factory.clone(),key, address_type))
    }
}