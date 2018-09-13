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
//! TREZOR compatible accounts (BIP44)
//!
use bitcoin::util::bip32::{ExtendedPubKey, ExtendedPrivKey,ChildNumber};
use bitcoin::util::address::Address;
use bitcoin::network::constants::Network;
use bitcoin::blockdata::script::Script;
use std::sync::Arc;
use std::error::Error;
use std::rc::Rc;
use std::cell::RefCell;
use keyfactory::KeyFactory;

use secp256k1::{Secp256k1, SecretKey, PublicKey};

/// Address type an account is using
#[derive(Eq, PartialEq)]
pub enum AccountAddressType {
    /// pay to public key hash (aka. legacy)
    P2PKH,
    /// pay to script hash of a witness script (aka. segwit in legacy address format)
    P2SHWH,
    /// pay to witness public key hash
    P2WKH,
}

#[derive(Debug)]
pub enum AddressChain {
    External,
    Internal,
}

#[derive(Debug)]
pub struct KeyPath {
    addr_chain: AddressChain,
    addr_index: u32,
}

impl KeyPath {
    pub fn new(addr_chain: AddressChain, addr_index: u32) -> Self {
        Self {
            addr_chain,
            addr_index,
        }
    }
}

#[derive(Debug)]
pub struct Utxo {
    value: u64,
    key_path: KeyPath,
}

impl Utxo {
    pub fn new(value: u64, key_path: KeyPath) -> Self {
        Self {
            value,
            key_path,
        }
    }
}

/// a TREZOR compatible account
pub struct Account {
    account_key: ExtendedPrivKey,
    pub address_type: AccountAddressType,
    #[allow(dead_code)]
    key_factory: Arc<KeyFactory>,
    network: Network,

    external_index: u32,
    internal_index: u32,
    external_sk_list: Vec<SecretKey>,
    internal_sk_list: Vec<SecretKey>,
    pub external_pk_list: Vec<PublicKey>,
    pub internal_pk_list: Vec<PublicKey>,

    utxo_list: Rc<RefCell<Vec<Utxo>>>,
}

impl Account {
    pub fn new (key_factory: Arc<KeyFactory>, account_key: ExtendedPrivKey, address_type: AccountAddressType, network: Network) -> Account {
        Account {
            key_factory,
            account_key,
            address_type,
            network,

            external_index: 0,
            internal_index: 0,
            external_sk_list: Vec::new(),
            internal_sk_list: Vec::new(),
            external_pk_list: Vec::new(),
            internal_pk_list: Vec::new(),

            utxo_list: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn grab_utxo(&self, utxo: Utxo) {
        self.utxo_list.borrow_mut().push(utxo);
    }

    pub fn get_utxo_list(&self) -> Rc<RefCell<Vec<Utxo>>> {
        Rc::clone(&self.utxo_list)
    }

    pub fn next_external_pk(&mut self) -> Result<PublicKey, Box<Error>> {
        let path: &[ChildNumber] = &[
            ChildNumber::Normal{index: 0},
            ChildNumber::Normal{index: self.external_index},
        ];
        self.external_index += 1;
        let extended_priv_key = self.account_key.derive_priv(&Secp256k1::new(),path)?;
        self.external_sk_list.push(extended_priv_key.secret_key);

        let extended_pub_key = ExtendedPubKey::from_private(&Secp256k1::new(), &extended_priv_key);
        self.external_pk_list.push(extended_pub_key.public_key);
        Ok(extended_pub_key.public_key)
    }

    pub fn next_internal_pk(&mut self) -> Result<PublicKey, Box<Error>> {
        let path: &[ChildNumber] = &[
            ChildNumber::Normal{index: 1},
            ChildNumber::Normal{index: self.internal_index},
        ];
        self.internal_index += 1;
        let extended_priv_key = self.account_key.derive_priv(&Secp256k1::new(), path)?;
        self.internal_sk_list.push(extended_priv_key.secret_key);

        let extended_pub_key = ExtendedPubKey::from_private(&Secp256k1::new(), &extended_priv_key);
        self.internal_pk_list.push(extended_pub_key.public_key);
        Ok(extended_pub_key.public_key)
    }

    pub fn addr_from_pk(&self, pk: &PublicKey) -> String {
        match self.address_type {
            AccountAddressType::P2PKH  => p2pkh_addr_from_public_key(pk, self.network),
            AccountAddressType::P2SHWH => p2shwh_addr_from_public_key(pk, self.network),
            AccountAddressType::P2WKH  => p2wkh_addr_from_public_key_bip0173(pk, self.network),
        }
    }

    pub fn script_from_pk(&self, pk: &PublicKey) -> Script {
        match self.address_type {
            AccountAddressType::P2PKH  => p2pkh_script_from_public_key(pk, self.network),
            AccountAddressType::P2SHWH => p2shwh_script_from_public_key(pk, self.network),
            AccountAddressType::P2WKH  => p2wkh_script_from_public_key(pk, self.network),
        }
    }

    pub fn new_address(&mut self) -> Result<String, Box<Error>> {
        let pk = self.next_external_pk()?;
        Ok(self.addr_from_pk(&pk))
    }

    pub fn new_change_address(&mut self) -> Result<String, Box<Error>> {
        let pk = self.next_internal_pk()?;
        Ok(self.addr_from_pk(&pk))
    }
}

pub fn p2pkh_addr_from_public_key(pk: &PublicKey, network: Network) -> String {
    let addr = Address::p2pkh(pk, network);
    addr.to_string()
}

pub fn p2shwh_addr_from_public_key(pk: &PublicKey, network: Network) -> String {
    let addr = Address::p2shwpkh(pk,network);
    addr.to_string()
}

pub fn p2wkh_addr_from_public_key_bip0173(pk: &PublicKey, network: Network) -> String {
    let addr = Address::p2wpkh(pk, network);
    addr.to_string()
}

pub fn p2pkh_script_from_public_key(pk: &PublicKey, network: Network) -> Script {
    let p2pkh_addr = Address::p2pkh(pk,network);
    p2pkh_addr.script_pubkey()
}

pub fn p2shwh_script_from_public_key(pk: &PublicKey, network: Network) -> Script {
    let addr = Address::p2shwpkh(pk,network);
    addr.script_pubkey()
}

pub fn p2wkh_script_from_public_key(pk: &PublicKey, network: Network) -> Script {
    let p2wkh_addr = Address::p2wpkh(pk,network);
    p2wkh_addr.script_pubkey()
}

#[cfg(test)]
mod test {
    use accountfactory::AccountFactory;
    use keyfactory::MasterKeyEntropy;
    use account::AccountAddressType;
    use accountfactory::BitcoindConfig;
    use bitcoin::network::constants::Network;
    use hex;

    #[test]
    fn test_p2pkh_public_key_generation() {
        fn get_external_pk_vec() -> Vec<String> {
            vec![
                "02ea034fa1bd663e56b014902d59a50f2cdca9991edb7584ae49b0f3b0904905fd".to_string(),
                "03d0faa428f4f8202318acfeb8269074df2bb24e8aefbe5745d4b8a4c2e800d5ed".to_string(),
                "02bedbe580f9b48fd3a63d383bd7378619343e7965f3ce250ee6de1b59a79336ac".to_string(),
                "0218fb5c9ff790be111cb8c980f7ec89be8786e91ce4145751d70dc775ee2de332".to_string(),
                "026160eef736bece582e20c72da48adbb6424377e97c7203913675cfed1820d2dd".to_string(),
            ]
        }
        fn get_internal_pk_vec() -> Vec<String> {
            vec![
                "03bc63404d619ed19cdc0d343ebcaaa93550656f8e3aaa49cef29a38f0e6f3a9de".to_string(),
                "033b47c69e29c4b99591ee5eeee2c37e28901a1c69369f637e0c71609dbe8ade53".to_string(),
                "028ec40eb8314a6a977ca816ed0d6807e4c3ddf2f14f42df435d7247b100091df0".to_string(),
                "022a329996e9d365f3f5cfc35966dd7d52afe26526cfe4673e79f099b060a32f68".to_string(),
                "037cc18470eed6675c57fc63e9da6bf94174e464676fdc6eae77ec778be959a758".to_string(),
            ]
        }

        let mut ac = AccountFactory::new_no_random(
            MasterKeyEntropy::Recommended, Network::Testnet, "", "easy", BitcoindConfig::default()).unwrap();
        let account = ac.account(0, AccountAddressType::P2PKH).unwrap();

        for expected_pk in get_external_pk_vec() {
            let pk = account.borrow_mut().next_external_pk().unwrap();
            assert_eq!(hex::encode(&pk.serialize()[..]), expected_pk);
        }

        for expected_pk in get_internal_pk_vec() {
            let pk = account.borrow_mut().next_internal_pk().unwrap();
            assert_eq!(hex::encode(&pk.serialize()[..]), expected_pk);
        }
    }

    #[test]
    fn test_p2wkh_public_key_generation() {
        let external_pk_vec = vec![
            "02a863d8d8852c4e2dccf510f306c59f8d626ce21d12320d186420226a5243d0b5",
            "0393b0aea13a6c1290a27de788a77e5a3b5d2abdd920689016415d53e97f5616b8",
            "028fd85e6951a9d4c0c96f017cd193e377f83d87d5f8625859e14c2da2a80913d8",
            "0254200ef7081b7a9225d72ea3ac3e31c0b65f807e412779ede30f4eb2aecf7eaf",
            "023d2c707f539d6d1a96b3b5249225e0ff6205a3ba7c5c280e4fd9441e0391a8a4",
        ];

        let internal_pk_vec = vec![
            "022aaac31d8fbb1161c96c5b866d0af6f20652df95342a89ddb9d554d35599480c",
            "039a7fb40f59111eb4b9d9e33572195d2dd1c9d32799a4c92f1b0d04c48a4baf3f",
            "0288239d7f610e643924cec725bac86bc0d3839d27096e6140e6766b59f6bbc9e2",
            "0271bc0074892a9b44de9bcf4aaae13c4a9354f9eca8d925c4fc322f7bbd19da69",
            "02a954c4e5275a094182284d96c9044dcb4d9d208cb23d4e181f05459c26e32778",
        ];

        let mut ac = AccountFactory::new_no_random(
            MasterKeyEntropy::Recommended, Network::Testnet, "", "easy", BitcoindConfig::default()).unwrap();
        let account = ac.account(0, AccountAddressType::P2WKH).unwrap();

        for expected_pk in external_pk_vec {
            let pk = account.borrow_mut().next_external_pk().unwrap();
            assert_eq!(hex::encode(&pk.serialize()[..]), expected_pk);
        }

        for expected_pk in internal_pk_vec {
            let pk = account.borrow_mut().next_internal_pk().unwrap();
            assert_eq!(hex::encode(&pk.serialize()[..]), expected_pk);
        }
    }
}