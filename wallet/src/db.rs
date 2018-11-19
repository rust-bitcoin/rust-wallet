use bitcoin::OutPoint;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rocksdb::{DB as RocksDB, ColumnFamilyDescriptor, Options, IteratorMode};
use byteorder::{ByteOrder, BigEndian};
use serde_json;

use std::collections::HashMap;

use account::{Utxo, SecretKeyHelper};
use accountfactory::{LockId, LockGroup};

static LAST_SEEN_BLOCK_HEIGHT: &'static [u8] = b"lsbh";
static UTXO_MAP_CF: &'static str = "utxo_map";
static EXTERNAL_SECRET_KEY_CF: &'static str = "eskcf";
static EXTERNAL_PUBLIC_KEY_CF: &'static str = "epkcf";
static INTERNAL_SECRET_KEY_CF: &'static str = "iskcf";
static INTERNAL_PUBLIC_KEY_CF: &'static str = "ipkcf";
static LOCK_GROUP_MAP_CF: &'static str = "lgm";

pub struct DB(RocksDB);

impl DB {
    pub fn new(db_path: String) -> Self {
        let utxo_map_cf= ColumnFamilyDescriptor::new(UTXO_MAP_CF, Options::default());
        let secret_key_cf = ColumnFamilyDescriptor::new(
            EXTERNAL_SECRET_KEY_CF,
            Options::default(),
        );
        let public_key_cf = ColumnFamilyDescriptor::new(
            EXTERNAL_PUBLIC_KEY_CF,
            Options::default(),
        );
        let internal_secret_key_cf = ColumnFamilyDescriptor::new(
            INTERNAL_SECRET_KEY_CF,
            Options::default(),
        );
        let internal_public_key_cf = ColumnFamilyDescriptor::new(
            INTERNAL_PUBLIC_KEY_CF,
            Options::default(),
        );
        let lock_group_map_cf = ColumnFamilyDescriptor::new(LOCK_GROUP_MAP_CF, Options::default());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = RocksDB::open_cf_descriptors(
            &db_opts,
            &db_path,
            vec![
                utxo_map_cf,
                secret_key_cf,
                public_key_cf,
                internal_secret_key_cf,
                internal_public_key_cf,
                lock_group_map_cf,
            ],
        ).unwrap();
        DB(db)
    }

    pub fn get_last_seen_block_height(&self) -> usize {
        self.0.get(LAST_SEEN_BLOCK_HEIGHT)
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

    pub fn get_external_secret_key_list(&self) -> Vec<(SecretKeyHelper, SecretKey)> {
        let cf = self.0.cf_handle(EXTERNAL_SECRET_KEY_CF).unwrap();
        let db_iterator = self.0.iterator_cf(cf, IteratorMode::Start).unwrap();

        let mut vec = Vec::new();
        for (key, val) in db_iterator {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let sk: [u8; 32] = serde_json::from_slice(&val).unwrap();
            let sk = SecretKey::from_slice(&Secp256k1::new(), &sk).unwrap();
            vec.push((key_helper, sk));
        }
        vec
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

    pub fn get_internal_secret_key_list(&self) -> Vec<(SecretKeyHelper, SecretKey)> {
        let cf = self.0.cf_handle(INTERNAL_SECRET_KEY_CF).unwrap();
        let db_iterator = self.0.iterator_cf(cf, IteratorMode::Start).unwrap();

        let mut vec = Vec::new();
        for (key, val) in db_iterator {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let sk: [u8; 32] = serde_json::from_slice(&val).unwrap();
            let sk = SecretKey::from_slice(&Secp256k1::new(), &sk).unwrap();
            vec.push((key_helper, sk));
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

    pub fn put_external_secret_key(&mut self, key_helper: &SecretKeyHelper, sk: &SecretKey) {
        let key = serde_json::to_vec(key_helper).unwrap();
        let val = serde_json::to_vec(sk).unwrap();
        let cf = self.0.cf_handle(EXTERNAL_SECRET_KEY_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn put_external_public_key(&mut self, key_helper: &SecretKeyHelper, pk: &PublicKey) {
        let key = serde_json::to_vec(key_helper).unwrap();
        let val = serde_json::to_vec(pk).unwrap();
        let cf = self.0.cf_handle(EXTERNAL_PUBLIC_KEY_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn put_internal_secret_key(&self, key_helper: &SecretKeyHelper, sk: &SecretKey) {
        let key = serde_json::to_vec(key_helper).unwrap();
        let val = serde_json::to_vec(sk).unwrap();
        let cf = self.0.cf_handle(INTERNAL_SECRET_KEY_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn put_internal_public_key(&self, key_helper: &SecretKeyHelper, pk: &PublicKey) {
        let key = serde_json::to_vec(key_helper).unwrap();
        let val = serde_json::to_vec(pk).unwrap();
        let cf = self.0.cf_handle(INTERNAL_PUBLIC_KEY_CF).unwrap();
        self.0.put_cf(cf, key.as_slice(), val.as_slice()).unwrap();
    }

    pub fn put_lock_group(&mut self, lock_id: &LockId, lock_group: &LockGroup) {
        let key = serde_json::to_vec(lock_id).unwrap();
        let value = serde_json::to_vec(lock_group).unwrap();
        let cf = self.0.cf_handle(LOCK_GROUP_MAP_CF).unwrap();
        self.0.put_cf(cf, &key, &value).unwrap();
    }
}