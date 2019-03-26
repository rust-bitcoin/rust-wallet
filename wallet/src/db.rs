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
use bitcoin::OutPoint;
use secp256k1::{Secp256k1, PublicKey};
use rocksdb::{DB as RocksDB, ColumnFamilyDescriptor, Options, IteratorMode};
use byteorder::{ByteOrder, BigEndian};
use serde_json;

use std::collections::HashMap;

use account::{Utxo, SecretKeyHelper, AccountAddressType};
use walletlibrary::{LockId, LockGroup};

static BIP39_RANDOMNESS: &'static [u8] = b"bip39_randomness";
static LAST_SEEN_BLOCK_HEIGHT: &'static [u8] = b"lsbh";
static UTXO_MAP_CF: &'static str = "utxo_map";
static EXTERNAL_PUBLIC_KEY_CF: &'static str = "epkcf";
static INTERNAL_PUBLIC_KEY_CF: &'static str = "ipkcf";
static P2PKH_ADDRESS_CF: &'static str = "p2pkh";
static P2SHWH_ADDRESS_CF: &'static str = "p2shwh";
static P2WKH_ADDRESS_CF: &'static str = "p2wkh";
static LOCK_GROUP_MAP_CF: &'static str = "lgm";

pub struct DB(RocksDB);

impl DB {
    pub fn new(db_path: String) -> Self {
        let utxo_map_cf = ColumnFamilyDescriptor::new(UTXO_MAP_CF, Options::default());
        let public_key_cf = ColumnFamilyDescriptor::new(EXTERNAL_PUBLIC_KEY_CF, Options::default());
        let internal_public_key_cf =
            ColumnFamilyDescriptor::new(INTERNAL_PUBLIC_KEY_CF, Options::default());
        let p2pkh_address_cf = ColumnFamilyDescriptor::new(P2PKH_ADDRESS_CF, Options::default());
        let p2shwh_address_cf = ColumnFamilyDescriptor::new(P2SHWH_ADDRESS_CF, Options::default());
        let p2wkh_address_cf = ColumnFamilyDescriptor::new(P2WKH_ADDRESS_CF, Options::default());
        let lock_group_map_cf = ColumnFamilyDescriptor::new(LOCK_GROUP_MAP_CF, Options::default());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = RocksDB::open_cf_descriptors(
            &db_opts,
            &db_path,
            vec![
                utxo_map_cf,
                public_key_cf,
                internal_public_key_cf,
                lock_group_map_cf,
                p2pkh_address_cf,
                p2shwh_address_cf,
                p2wkh_address_cf,
            ],
        )
        .unwrap();
        DB(db)
    }

    pub fn has_bip39_randomness(&self) -> bool {
        self.0.get(BIP39_RANDOMNESS).unwrap().is_some()
    }

    pub fn get_bip39_randomness(&self) -> Vec<u8> {
        let randomness = self.0.get(BIP39_RANDOMNESS).unwrap().unwrap();
        (*randomness).to_vec()
    }

    pub fn put_bip39_randomness(&self, randomness: &[u8]) {
        self.0.put(BIP39_RANDOMNESS, randomness).unwrap();
    }

    pub fn get_last_seen_block_height(&self) -> usize {
        self.0
            .get(LAST_SEEN_BLOCK_HEIGHT)
            .unwrap()
            .map(|val| BigEndian::read_u32(&*val) as usize)
            .unwrap_or(1)
    }

    pub fn put_last_seen_block_height(&mut self, last_seen_block_height: u32) {
        let mut buff = [0u8; 4];
        BigEndian::write_u32(&mut buff, last_seen_block_height);
        self.0.put(LAST_SEEN_BLOCK_HEIGHT, &buff).unwrap();
    }

    pub fn get_utxo_map(&self) -> HashMap<OutPoint, Utxo> {
        let cf = self.0.cf_handle(UTXO_MAP_CF).unwrap();
        let db_iterator = self.0.iterator_cf(cf, IteratorMode::Start).unwrap();

        let mut utxo_map = HashMap::new();
        for (key, val) in db_iterator {
            let out_point: OutPoint = serde_json::from_slice(&key).unwrap();
            let utxo: Utxo = serde_json::from_slice(&val).unwrap();
            utxo_map.insert(out_point, utxo);
        }
        utxo_map
    }

    pub fn put_utxo(&mut self, op: &OutPoint, utxo: &Utxo) {
        let key = serde_json::to_vec(op).unwrap();
        let val = serde_json::to_vec(utxo).unwrap();
        let cf = self.0.cf_handle(UTXO_MAP_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn delete_utxo(&self, op: &OutPoint) {
        let key = serde_json::to_vec(op).unwrap();
        let cf = self.0.cf_handle(UTXO_MAP_CF).unwrap();
        self.0.delete_cf(cf, key.as_slice()).unwrap();
    }

    pub fn get_external_public_key_list(&self) -> Vec<(SecretKeyHelper, PublicKey)> {
        let cf = self.0.cf_handle(EXTERNAL_PUBLIC_KEY_CF).unwrap();
        let db_iterator = self.0.iterator_cf(cf, IteratorMode::Start).unwrap();

        let mut vec = Vec::new();
        for (key, val) in db_iterator {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let pk: Vec<u8> = serde_json::from_slice(&val).unwrap();
            let pk = PublicKey::from_slice(&Secp256k1::new(), pk.as_slice()).unwrap();
            vec.push((key_helper, pk));
        }
        vec
    }

    pub fn get_internal_public_key_list(&self) -> Vec<(SecretKeyHelper, PublicKey)> {
        let cf = self.0.cf_handle(INTERNAL_PUBLIC_KEY_CF).unwrap();
        let db_iterator = self.0.iterator_cf(cf, IteratorMode::Start).unwrap();

        let mut vec = Vec::new();
        for (key, val) in db_iterator {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let pk: Vec<u8> = serde_json::from_slice(&val).unwrap();
            let pk = PublicKey::from_slice(&Secp256k1::new(), pk.as_slice()).unwrap();
            vec.push((key_helper, pk));
        }
        vec
    }

    pub fn get_full_address_list(&self) -> Vec<String> {
        let p2pkh = self.get_account_address_list(AccountAddressType::P2PKH);
        let p2shwh = self.get_account_address_list(AccountAddressType::P2SHWH);
        let p2wkh = self.get_account_address_list(AccountAddressType::P2WKH);
        let full = [&p2pkh[..], &p2shwh[..], &p2wkh[..]].concat();
        full
    }
    pub fn get_account_address_list(&self, addr_type: AccountAddressType) -> Vec<String> {
        let name = match addr_type {
            AccountAddressType::P2PKH => P2PKH_ADDRESS_CF,
            AccountAddressType::P2SHWH => P2SHWH_ADDRESS_CF,
            AccountAddressType::P2WKH => P2WKH_ADDRESS_CF,
        };
        let cf = self.0.cf_handle(name).unwrap();
        let db_iterator = self.0.iterator_cf(cf, IteratorMode::Start).unwrap();
        let mut vec = Vec::new();
        for (key, _) in db_iterator {
            let addr: String = serde_json::from_slice(&key).unwrap();
            vec.push(addr);
        }
        vec
    }

    pub fn put_external_public_key(&mut self, key_helper: &SecretKeyHelper, pk: &PublicKey) {
        let key = serde_json::to_vec(key_helper).unwrap();
        let val = serde_json::to_vec(pk).unwrap();
        let cf = self.0.cf_handle(EXTERNAL_PUBLIC_KEY_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn put_internal_public_key(&self, key_helper: &SecretKeyHelper, pk: &PublicKey) {
        let key = serde_json::to_vec(key_helper).unwrap();
        let val = serde_json::to_vec(pk).unwrap();
        let cf = self.0.cf_handle(INTERNAL_PUBLIC_KEY_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn put_address(&self, addr_type: AccountAddressType, address: String) {
        let key = serde_json::to_vec(&address).unwrap();
        match addr_type {
            AccountAddressType::P2PKH => {
                let cf = self.0.cf_handle(P2PKH_ADDRESS_CF).unwrap();
                self.0.put_cf(cf, key.as_slice(), &[]).unwrap();
            }
            AccountAddressType::P2SHWH => {
                let cf = self.0.cf_handle(P2SHWH_ADDRESS_CF).unwrap();
                self.0.put_cf(cf, key.as_slice(), &[]).unwrap();
            }
            AccountAddressType::P2WKH => {
                let cf = self.0.cf_handle(P2WKH_ADDRESS_CF).unwrap();
                self.0.put_cf(cf, key.as_slice(), &[]).unwrap();
            }
        }
    }

    pub fn put_lock_group(&mut self, lock_id: &LockId, lock_group: &LockGroup) {
        let key = serde_json::to_vec(lock_id).unwrap();
        let value = serde_json::to_vec(lock_group).unwrap();
        let cf = self.0.cf_handle(LOCK_GROUP_MAP_CF).unwrap();
        self.0.put_cf(cf, &key, &value).unwrap();
    }
}
