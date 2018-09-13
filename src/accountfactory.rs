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
use bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use keyfactory::{KeyFactory, MasterKeyEntropy, Seed};
use error::WalletError;
use mnemonic::Mnemonic;
use account::{Account,AccountAddressType,Utxo,KeyPath,AddressChain};
use std::sync::Arc;
use std::rc::Rc;
use std::cell::RefCell;

use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, SerializedRawTransaction};

pub struct BitcoindConfig {
    url:      String,
    user:     String,
    password: String,
}

impl BitcoindConfig {
    pub fn new(url: String, user: String, password: String) -> Self {
        Self {
            url,
            user,
            password,
        }
    }
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
            url:      String::new(),
            user:     String::new(),
            password: String::new(),
        }
    }
}

// a factory for TREZOR (BIP44) compatible accounts
pub struct AccountFactory {
    master_key: ExtendedPrivKey,
    mnemonic: Mnemonic,
    encrypted: Vec<u8>,
    key_factory: Arc<KeyFactory>,
    account_list: Vec<Rc<RefCell<Account>>>,
    network: Network,
    cfg: BitcoindConfig,
}

impl AccountFactory {
    /// initialize with new random master key
    pub fn new (entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str, cfg: BitcoindConfig) -> Result<AccountFactory, WalletError> {
        let key_factory = KeyFactory::new();
        let (master_key, mnemonic, encrypted) = key_factory.new_master_private_key (entropy, network, passphrase, salt)?;
        Ok(AccountFactory{
            key_factory: Arc::new(key_factory),
            master_key,
            mnemonic,
            encrypted,
            account_list: Vec::new(),
            network,
            cfg,
        })
    }

    pub fn new_no_random (entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str, cfg: BitcoindConfig) -> Result<AccountFactory, WalletError> {
        let key_factory = KeyFactory::new();
        let (master_key, mnemonic, encrypted, _) = key_factory.new_master_private_key_no_random (entropy, network, passphrase, salt)?;
        println!("{}", mnemonic.to_string());
        Ok(AccountFactory{
            key_factory: Arc::new(key_factory),
            master_key,
            mnemonic,
            encrypted,
            account_list: Vec::new(),
            network,
            cfg,
        })
    }

    /// decrypt stored master key
    pub fn decrypt (encrypted: &[u8], network: Network, passphrase: &str, salt: &str, cfg: BitcoindConfig) -> Result<AccountFactory, WalletError> {
        let mnemonic = Mnemonic::new (encrypted, passphrase)?;
        let key_factory = KeyFactory::new();
        let master_key = key_factory.master_private_key(network, &Seed::new(&mnemonic, salt))?;
        Ok(AccountFactory{
            key_factory: Arc::new(key_factory),
            master_key,
            mnemonic,
            encrypted: encrypted.to_vec(),
            account_list: Vec::new(),
            network,
            cfg,
        })
    }

    /// get a copy of the master private key
    pub fn master_private (&self) -> ExtendedPrivKey {
        self.master_key.clone()
    }

    /// get a copy of the master public key
    pub fn master_public (&self) -> ExtendedPubKey {
        self.key_factory.extended_public_from_private(&self.master_key)
    }

    pub fn mnemonic (&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn encrypted (&self) -> Vec<u8> {
        self.encrypted.clone()
    }

    /// get an account
    pub fn account (&mut self, account_number: u32, address_type: AccountAddressType) -> Result<Rc<RefCell<Account>>, WalletError> {
        let mut key = match address_type {
            AccountAddressType::P2PKH  => self.key_factory.private_child(&self.master_key, ChildNumber::Hardened{index: 44})?,
            AccountAddressType::P2SHWH => self.key_factory.private_child(&self.master_key, ChildNumber::Hardened{index: 49})?,
            AccountAddressType::P2WKH  => self.key_factory.private_child(&self.master_key, ChildNumber::Hardened{index: 84})?,
        };
        key = match key.network {
            Network::Bitcoin => self.key_factory.private_child(&key, ChildNumber::Hardened{index: 0})?,
            Network::Testnet => self.key_factory.private_child(&key, ChildNumber::Hardened{index: 1})?,
            // TODO(evg): `ChildNumber::Hardened{index: 2}` is it correct?
            Network::Regtest => self.key_factory.private_child(&key, ChildNumber::Hardened{index: 2})?,
        };
        key = self.key_factory.private_child(&key, ChildNumber::Hardened{index: account_number})?;

        let account = Rc::new(RefCell::new(Account::new(self.key_factory.clone(),key, address_type, self.network)));
        self.account_list.push(Rc::clone(&account));
        Ok(account)
    }

    // TODO(evg): impl error handling
    pub fn sync_with_blockchain(&self) {
        let client = BitcoinCoreClient::new(&self.cfg.url, &self.cfg.user, &self.cfg.password);

        let block_height = client.get_block_count()
            .unwrap()
            .unwrap()
            .as_i64();

        for i in 1..block_height+1 {
            let block_hash = client.get_block_hash(i as u32)
                .unwrap()
                .unwrap();

            let block = client.get_block(&block_hash)
                .unwrap()
                .unwrap();

            for txid in block.tx {
                let tx = client.get_transaction(&txid)
                    .unwrap()
                    .unwrap();
                let tx_hex: SerializedRawTransaction = tx.hex;
                let tx: BitcoinTransaction = BitcoinTransaction::from(tx_hex);

                for account in &self.account_list {
                    let account = account.borrow_mut();
                    for output in &tx.output {
                        let actual= &output.script_pubkey.to_bytes();
                        let mut joined = account.external_pk_list.clone();
                        joined.extend_from_slice(&account.internal_pk_list);

                        if output.script_pubkey.is_p2pkh() && account.address_type == AccountAddressType::P2PKH {
                            for pk_index in 0..joined.len() {
                                let pk = &joined[pk_index];
                                let script = account.script_from_pk(pk);
                                let expected = &script.to_bytes();
                                if actual == expected {
                                    let key_path = KeyPath::new(AddressChain::External, pk_index as u32);
                                    account.grab_utxo(Utxo::new(output.value, key_path));
                                }
                            }
                        }

                        if output.script_pubkey.is_p2sh() && account.address_type == AccountAddressType::P2SHWH {
                            for pk_index in 0..joined.len() {
                                let pk = &joined[pk_index];
                                let script = account.script_from_pk(pk);
                                let expected = &script.to_bytes();
                                if actual == expected {
                                    let key_path = KeyPath::new(AddressChain::External, pk_index as u32);
                                    account.grab_utxo(Utxo::new(output.value, key_path));
                                }
                            }
                        }

                        if output.script_pubkey.is_v0_p2wpkh() && account.address_type == AccountAddressType::P2WKH {
                            for pk_index in 0..joined.len() {
                                let pk = &joined[pk_index];
                                let script = account.script_from_pk(pk);
                                let expected = &script.to_bytes();
                                if actual == expected {
                                    let key_path = KeyPath::new(AddressChain::External, pk_index as u32);
                                    account.grab_utxo(Utxo::new(output.value, key_path));
                                }
                            }
                        }
                    }

                }
            }
        }
    }
}