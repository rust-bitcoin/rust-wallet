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

use bitcoin::{
    util::{
        bip32::{ExtendedPubKey, ExtendedPrivKey,ChildNumber},
        bip143,
        address::Address,
    },

    blockdata::transaction::{OutPoint, Transaction as BitcoinTransaction, TxIn, TxOut},
    blockdata::script::{Script, Builder},
    blockdata::block::Block as WireBlock,

    network::constants::Network,
};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, TransactionId, Block};
use rocksdb::{DB, ColumnFamilyDescriptor, Options, IteratorMode};
use byteorder::{ByteOrder, BigEndian};
use serde_json;

use std::{
    error::Error,
    sync::{Arc, RwLock},
    collections::HashMap,
    str::FromStr,
};

use error::WalletError;
use mnemonic::Mnemonic;
use keyfactory::{KeyFactory, MasterKeyEntropy};
use account::{Account, AccountAddressType, Utxo, KeyPath, AddressChain, SecretKeyHelper};

static LAST_SEEN_BLOCK_HEIGHT: &'static [u8] = b"lsbh";
pub static UTXO_MAP_CF: &'static str = "utxo_map";
pub static SECRET_KEY_CF: &'static str = "skcf";
pub static PUBLIC_KEY_CF: &'static str = "pkcf";
pub static INTERNAL_SECRET_KEY_CF: &'static str = "internal_skcf";
pub static INTERNAL_PUBLIC_KEY_CF: &'static str = "internal_pkcf";

static LOCK_GROUP_MAP_CF: &'static str = "lgm";

pub static DEFAULT_BITCOIND_RPC_CONNECT: &'static str = "http://127.0.0.1:18332";
pub static DEFAULT_BITCOIND_RPC_USER: &'static str = "user";
pub static DEFAULT_BITCOIND_RPC_PASSWORD: &'static str = "password";
pub static DEFAULT_ZMQ_PUB_RAW_BLOCK_ENDPOINT: &'static str = "tcp://localhost:18501";
pub static DEFAULT_ZMQ_PUB_RAW_TX_ENDPOINT: &'static str = "tcp://localhost:18501";

pub const DEFAULT_NETWORK: Network = Network::Regtest;
pub const DEFAULT_ENTROPY: MasterKeyEntropy = MasterKeyEntropy::Recommended;
pub static DEFAULT_PASSPHRASE: &'static str = "";
pub static DEFAULT_SALT: &'static str = "easy";
pub static DEFAULT_DB_PATH: &'static str = "rocks.db";

#[derive(Clone)]
pub struct BitcoindConfig {
    url:      String,
    user:     String,
    password: String,
    pub zmq_pub_raw_block: String,
    zmq_pub_raw_tx:    String,
}

impl BitcoindConfig {
    pub fn new(url: String, user: String, password: String, zmq_pub_raw_block: String, zmq_pub_raw_tx: String) -> Self {
        Self {
            url,
            user,
            password,
            zmq_pub_raw_block,
            zmq_pub_raw_tx,
        }
    }
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        BitcoindConfig::new(
            DEFAULT_BITCOIND_RPC_CONNECT.to_string(),
            DEFAULT_BITCOIND_RPC_USER.to_string(),
            DEFAULT_BITCOIND_RPC_PASSWORD.to_string(),
            DEFAULT_ZMQ_PUB_RAW_BLOCK_ENDPOINT.to_string(),
            DEFAULT_ZMQ_PUB_RAW_TX_ENDPOINT.to_string(),
        )
    }
}

pub struct WalletConfigBuilder {
    inner: WalletConfig,
}

impl WalletConfigBuilder {
    pub fn new() -> Self {
        Self {
            inner: WalletConfig::default(),
        }
    }

    pub fn network(mut self, network: Network) -> WalletConfigBuilder {
        self.inner.network = network;
        self
    }

    pub fn db_path(mut self, db_path: String) -> WalletConfigBuilder {
        self.inner.db_path = db_path;
        self
    }

    pub fn finalize(self) -> WalletConfig {
        self.inner
    }
}

pub struct WalletConfig {
    network: Network,
    entropy: MasterKeyEntropy,
    passphrase: String,
    salt: String,
    db_path: String
}

impl WalletConfig {
    pub fn new(network: Network, entropy: MasterKeyEntropy, passphrase: String, salt: String, db_path: String) -> Self {
        Self {
            network,
            entropy,
            passphrase,
            salt,
            db_path,
        }
    }

    pub fn with_db_path(db_path: String) -> Self {
        let mut wc = Self::default();
        wc.db_path = db_path;
        wc
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig::new(
            DEFAULT_NETWORK,
            DEFAULT_ENTROPY,
            DEFAULT_PASSPHRASE.to_string(),
            DEFAULT_SALT.to_string(),
            DEFAULT_DB_PATH.to_string(),
        )
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Serialize)]
pub struct LockId(u64);

impl LockId {
    fn new() -> Self {
        LockId(0)
    }

    fn incr(&mut self) {
        self.0 += 1;
    }
}

impl From<u64> for LockId {
    fn from(value: u64) -> LockId {
        LockId(value)
    }
}

impl From<LockId> for u64 {
    fn from(lock_id: LockId) -> u64 {
        lock_id.0
    }
}

// TODO(evg): impl iter?
#[derive(Serialize, Clone)]
struct LockGroup(Vec<OutPoint>);

struct LockGroupMap(HashMap<LockId, LockGroup>);

impl LockGroupMap {
    fn new() -> Self {
        LockGroupMap(HashMap::new())
    }

    fn lock_group(&mut self, lock_id: LockId, lock_group: LockGroup) {
        self.0.insert(lock_id, lock_group);
    }

    fn unlock_group(&mut self, lock_id: LockId) {
        self.0.remove(&lock_id).unwrap();
    }

    fn is_locked(&self, op: &OutPoint) -> bool {
        for (_, lock_group) in &self.0 {
            for item in &lock_group.0 {
                if op == item {
                    return true;
                }
            }
        }
        false
    }
}

// a factory for TREZOR (BIP44) compatible accounts
pub struct AccountFactory {
    master_key: ExtendedPrivKey,
    mnemonic: Mnemonic,
    encrypted: Vec<u8>,
    key_factory: Arc<KeyFactory>,
    account_list: Vec<Arc<RwLock<Account>>>,
    network: Network,
    #[allow(dead_code)]
    cfg: BitcoindConfig,
    pub client: BitcoinCoreClient,
    last_seen_block_height: usize,
    op_to_utxo: HashMap<OutPoint, Utxo>,
    // TODO(evg): add LockId type, LockGroup type
    next_lock_id: LockId,
    locked_coins: LockGroupMap,
    db: Arc<RwLock<DB>>,
}

impl AccountFactory {
    /// initialize with new random master key
    // TODO(evg): avoid code duplicate
//    pub fn new (entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str, cfg: BitcoindConfig) -> Result<AccountFactory, WalletError> {
//        let key_factory = KeyFactory::new();
//        let (master_key, mnemonic, encrypted) = key_factory.new_master_private_key (entropy, network, passphrase, salt)?;
//        let client = BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password);
//        let db = DB::open_default("rocks.db").unwrap();
//        Ok(AccountFactory{
//            key_factory: Arc::new(key_factory),
//            master_key,
//            mnemonic,
//            encrypted,
//            account_list: Vec::new(),
//            network,
//            cfg,
//            client,
//            last_seen_block_height: 1,
//            op_to_utxo: HashMap::new(),
//            db: Arc::new(RwLock::new(db)),
//        })
//    }

    pub fn new_no_random (wc: WalletConfig, btc_cfg: BitcoindConfig) -> Result<AccountFactory, WalletError> {
        let key_factory = KeyFactory::new();
        let (master_key, mnemonic, encrypted, _) = key_factory.new_master_private_key_no_random (wc.entropy, wc.network, &wc.passphrase, &wc.salt)?;
        // println!("{}", mnemonic.to_string());
        let client = BitcoinCoreClient::new(&btc_cfg.url, &btc_cfg.user, &btc_cfg.password);

        let utxo_map_cf= ColumnFamilyDescriptor::new(UTXO_MAP_CF, Options::default());
        let secret_key_cf = ColumnFamilyDescriptor::new(SECRET_KEY_CF, Options::default());
        let public_key_cf = ColumnFamilyDescriptor::new(PUBLIC_KEY_CF, Options::default());

        let internal_secret_key_cf = ColumnFamilyDescriptor::new(INTERNAL_SECRET_KEY_CF, Options::default());
        let internal_public_key_cf = ColumnFamilyDescriptor::new(INTERNAL_PUBLIC_KEY_CF, Options::default());

        let lock_group_map_cf = ColumnFamilyDescriptor::new(LOCK_GROUP_MAP_CF, Options::default());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = DB::open_cf_descriptors(&db_opts, &wc.db_path, vec![
            utxo_map_cf, secret_key_cf, public_key_cf, internal_secret_key_cf, internal_public_key_cf, lock_group_map_cf]).unwrap();

        // let db = DB::open_default("rocks.db").unwrap();
        let last_seen_block_height = db.get(LAST_SEEN_BLOCK_HEIGHT)
            .unwrap()
            .map(|val| BigEndian::read_u32(&*val) as usize)
            .unwrap_or(1);

        let mut op_to_utxo = HashMap::new();
        let cf = db.cf_handle(UTXO_MAP_CF).unwrap();
        let iter = db.iterator_cf(cf, IteratorMode::Start).unwrap();
        for (key, val) in iter {
            let out_point: OutPoint = serde_json::from_slice(&key).unwrap();
            let utxo: Utxo = serde_json::from_slice(&val).unwrap();
            op_to_utxo.insert(out_point, utxo);
        }

        let cf = db.cf_handle(SECRET_KEY_CF).unwrap();
        let iter = db.iterator_cf(cf, IteratorMode::Start).unwrap();

        let public_cf = db.cf_handle(PUBLIC_KEY_CF).unwrap();
        let public_iter = db.iterator_cf(public_cf, IteratorMode::Start).unwrap();

        let internal_cf = db.cf_handle(INTERNAL_SECRET_KEY_CF).unwrap();
        let internal_iter = db.iterator_cf(internal_cf, IteratorMode::Start).unwrap();

        let internal_public_cf = db.cf_handle(INTERNAL_PUBLIC_KEY_CF).unwrap();
        let internal_public_iter = db.iterator_cf(internal_public_cf, IteratorMode::Start).unwrap();

        let mut ac = AccountFactory{
            key_factory: Arc::new(key_factory),
            master_key,
            mnemonic,
            encrypted,
            account_list: Vec::new(),
            network: wc.network,
            cfg: btc_cfg,
            client,
            last_seen_block_height,
            op_to_utxo,
            next_lock_id: LockId::new(),
            locked_coins: LockGroupMap::new(),
            db: Arc::new(RwLock::new(db)),
        };
        ac.initialize();
        for (_, val) in &ac.op_to_utxo {
            let guarded_acc = &*ac.account_list[usize::from(val.addr_type.clone())];
            let acc = guarded_acc.write().unwrap();
            acc.utxo_list.write().unwrap().insert(val.out_point, val.clone());
        }

        for (key, val) in iter {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let sk: [u8; 32] = serde_json::from_slice(&val).unwrap();
            let sk = SecretKey::from_slice(&Secp256k1::new(), &sk).unwrap();

            let guarded_acc = &*ac.account_list[usize::from(key_helper.addr_type.clone())];
            let mut acc = guarded_acc.write().unwrap();

            acc.external_sk_list.push(sk);
        }

        for (key, val) in public_iter {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let pk: Vec<u8> = serde_json::from_slice(&val).unwrap();
            let pk = PublicKey::from_slice(&Secp256k1::new(), pk.as_slice()).unwrap();

            let guarded_acc = &*ac.account_list[usize::from(key_helper.addr_type.clone())];
            let mut acc = guarded_acc.write().unwrap();

            acc.external_pk_list.push(pk);
        }

        for (key, val) in internal_iter {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let sk: [u8; 32] = serde_json::from_slice(&val).unwrap();
            let sk = SecretKey::from_slice(&Secp256k1::new(), &sk).unwrap();

            let guarded_acc = &*ac.account_list[usize::from(key_helper.addr_type.clone())];
            let mut acc = guarded_acc.write().unwrap();

            acc.internal_sk_list.push(sk);
        }

        for (key, val) in internal_public_iter {
            let key_helper: SecretKeyHelper = serde_json::from_slice(&key).unwrap();
            let pk: Vec<u8> = serde_json::from_slice(&val).unwrap();
            let pk = PublicKey::from_slice(&Secp256k1::new(), pk.as_slice()).unwrap();

            let guarded_acc = &*ac.account_list[usize::from(key_helper.addr_type.clone())];
            let mut acc = guarded_acc.write().unwrap();

            acc.internal_pk_list.push(pk);
        }
        Ok(ac)
    }

    /// decrypt stored master key
//    pub fn decrypt (encrypted: &[u8], network: Network, passphrase: &str, salt: &str, cfg: BitcoindConfig) -> Result<AccountFactory, WalletError> {
//        let mnemonic = Mnemonic::new (encrypted, passphrase)?;
//        let key_factory = KeyFactory::new();
//        let master_key = key_factory.master_private_key(network, &Seed::new(&mnemonic, salt))?;
//        let client = BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password);
//        let db = DB::open_default("rocks.db").unwrap();
//        Ok(AccountFactory{
//            key_factory: Arc::new(key_factory),
//            master_key,
//            mnemonic,
//            encrypted: encrypted.to_vec(),
//            account_list: Vec::new(),
//            network,
//            cfg,
//            client,
//            last_seen_block_height: 1,
//            op_to_utxo: HashMap::new(),
//            db: Arc::new(RwLock::new(db)),
//        })
//    }

    pub fn initialize(&mut self) {
        self.new_account(0, AccountAddressType::P2PKH).unwrap();
        self.new_account(0, AccountAddressType::P2SHWH).unwrap();
        self.new_account(0, AccountAddressType::P2WKH).unwrap();
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
    pub fn new_account (&mut self, account_number: u32, address_type: AccountAddressType) -> Result<Arc<RwLock<Account>>, WalletError> {
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

        let account = Arc::new(RwLock::new(Account::new(self.key_factory.clone(),key, address_type, self.network, Arc::clone(&self.db))));
        self.account_list.push(Arc::clone(&account));
        Ok(account)
    }

    pub fn get_account(&self, address_type: AccountAddressType) -> Arc<RwLock<Account>> {
        let index: usize = address_type.into();
        Arc::clone(&self.account_list[index])
    }

    pub fn get_utxo_list(&self) -> Vec<Utxo> {
        let mut joined = Vec::new();
        for account in &self.account_list {
            let account_utxo_list = &account.read().unwrap().get_utxo_list();
            // joined.extend_from_slice(&*account_utxo_list.read().unwrap());
            let account_utxo_list = &*account_utxo_list.read().unwrap();
            for (_, val) in account_utxo_list {
                joined.push(val.clone());
            }
        }
        joined
    }

    pub fn wallet_balance(&self) -> u64 {
        let utxo_list = self.get_utxo_list();

        let mut balance: u64 = 0;
        for utxo in utxo_list {
            balance += utxo.value;
        }
        balance
    }

    pub fn unlock_coins(&mut self, lock_id: LockId) {
        self.locked_coins.unlock_group(lock_id);
    }

    pub fn send_coins(&mut self, addr_str: String, amt: u64, lock_coins: bool, witness_only: bool) -> Result<(BitcoinTransaction, LockId), Box<Error>> {
        let utxo_list = self.get_utxo_list();

        let mut total = 0;
        let mut subset = Vec::new();
        for utxo in utxo_list {
            if self.locked_coins.is_locked(&utxo.out_point) {
                continue
            }

            if witness_only {
                if utxo.addr_type != AccountAddressType::P2WKH {
                    continue
                }
            }

            total += utxo.value;
            subset.push(utxo.out_point);

            if total >= amt + 10000 {
                break
            }
        }

        let tx = self.make_tx(subset.clone(), addr_str, amt)?;
        if lock_coins {
            let lock_group = LockGroup(subset);
            self.locked_coins.lock_group(self.next_lock_id.clone(), lock_group.clone());

            let cf = self.db.read().unwrap().cf_handle(LOCK_GROUP_MAP_CF).unwrap();
            let key = serde_json::to_vec(&self.next_lock_id.clone()).unwrap();
            let value = serde_json::to_vec(&lock_group).unwrap();
            self.db.write().unwrap().put_cf(cf, &key, &value).unwrap();

            let rez = self.next_lock_id.clone();
            self.next_lock_id.incr();
            return Ok((tx, rez));
        };
        Ok((tx, LockId::new()))
    }

    // TODO(evg): add version, lock_time param?
    pub fn make_tx(&mut self, ops: Vec<OutPoint>, addr_str: String, amt: u64) -> Result<BitcoinTransaction, Box<Error>> {
        let addr: Address = Address::from_str(&addr_str).unwrap();

        let mut tx = BitcoinTransaction {
            version:   0,
            lock_time: 0,
            input:     Vec::new(),
            output:    Vec::new(),
        };

        let mut total = 0;
        for op in &ops {
            let utxo = self.op_to_utxo.get(op).unwrap();
            total += utxo.value;

            let input = TxIn{
                previous_output: *op,
                script_sig:      Script::new(),
                sequence:        0xFFFFFFFF,
                witness:         Vec::new(),
            };
            tx.input.push(input);
        }

        if total < (amt + 10_000) {
            return Err(From::from("something went wrong..."));
        }

        // dest output
        let output = TxOut{
            value: amt,
            script_pubkey: addr.script_pubkey(),
        };
        tx.output.push(output);

        let change_addr = {
            let mut account = self.account_list[AccountAddressType::P2WKH as usize].write().unwrap();
            let change_addr = account.new_change_address().unwrap();
            Address::from_str(&change_addr).unwrap()
        };

        let change_output = TxOut{
            value: total - amt - 10_000, // subtract fee
            script_pubkey: change_addr.script_pubkey(),
        };
        tx.output.push(change_output);

        // sign tx
        for i in 0..ops.len() {
            let op = &ops[i];
            let utxo = self.op_to_utxo.get(op).unwrap();

            let account = self.account_list[utxo.account_index as usize].read().unwrap();

            let ctx = Secp256k1::new();
            let sk = account.get_sk(&utxo.key_path);
            let pk = PublicKey::from_secret_key(&ctx, &sk);

            // TODO(evg): do not hardcode bitcoin's network param
            match utxo.addr_type {
                AccountAddressType::P2PKH => {
                    let pk_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();

                    // TODO(evg): use SigHashType enum
                    let signature = ctx.sign(
                        &Message::from(tx.signature_hash(i, &pk_script, 0x1).into_bytes()),
                        &sk,
                    );

                    let mut serialized_sig = signature.serialize_der(&ctx);
                    serialized_sig.push(0x1);

                    let script = Builder::new()
                        .push_slice(serialized_sig.as_slice())
                        .push_slice(&pk.serialize())
                        .into_script();
                    tx.input[i].script_sig = script;
                },
                AccountAddressType::P2SHWH => {
                    let pk_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();
                    let pk_script_p2wpkh = Address::p2wpkh(&pk, Network::Bitcoin).script_pubkey();

                    let tx_sig_hash = bip143::SighashComponents::new(&tx).
                        sighash_all(
                            &tx.input[i],
                            &pk_script,
                            utxo.value,
                        );

                    let signature = ctx.sign(
                        &Message::from(tx_sig_hash.into_bytes()),
                        &sk,
                    );

                    let mut serialized_sig = signature.serialize_der(&ctx);
                    serialized_sig.push(0x1);

                    tx.input[i].witness.push(serialized_sig);
                    tx.input[i].witness.push(pk.serialize().to_vec());

                    tx.input[i].script_sig = Builder::new()
                        .push_slice(pk_script_p2wpkh.as_bytes())
                        .into_script();
                },
                AccountAddressType::P2WKH => {
                    let pk_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();

                    let tx_sig_hash = bip143::SighashComponents::new(&tx).
                        sighash_all(
                            &tx.input[i],
                            &pk_script,
                            utxo.value,
                        );

                    let signature = ctx.sign(
                        &Message::from(tx_sig_hash.into_bytes()),
                        &sk,
                    );

                    let mut serialized_sig = signature.serialize_der(&ctx);
                    serialized_sig.push(0x1);

                    tx.input[i].witness.push(serialized_sig);
                    tx.input[i].witness.push(pk.serialize().to_vec());
                }
            }
        }
        Ok(tx)
    }

    pub fn process_tx(&mut self, txid: &TransactionId, tx: &BitcoinTransaction) {
        for account_index in 0..self.account_list.len() {
            for input_index in 0..tx.input.len() {
                let input = &tx.input[input_index];
                if self.op_to_utxo.contains_key(&input.previous_output) {
                    {
                        // remove from account utxo map
                        let utxo = self.op_to_utxo.get(&input.previous_output).unwrap();
                        let acc = self.account_list[usize::from(utxo.addr_type.clone())].write().unwrap();
                        let mut utxo_map = acc.utxo_list.write().unwrap();
                        utxo_map.remove(&input.previous_output).unwrap();

                        // remove from db
                        let key = serde_json::to_vec(&utxo.out_point).unwrap();
                        let cf = self.db.write().unwrap().cf_handle(UTXO_MAP_CF).unwrap();
                        self.db.write().unwrap().delete_cf(cf, key.as_slice()).unwrap();
                    }

                    // remove from account_factory utxo_map
                    self.op_to_utxo.remove(&input.previous_output).unwrap();
                }
            }

            let mut account = self.account_list[account_index].write().unwrap();

            for output_index in 0..tx.output.len() {
                let output = &tx.output[output_index];
                let actual = &output.script_pubkey.to_bytes();
                let mut joined = account.external_pk_list.clone();
                joined.extend_from_slice(&account.internal_pk_list);

                // TODO(evg): something better?
                let external_pk_list_len = account.external_pk_list.len();
                let get_pk_index = |mut raw: usize| -> (usize, AddressChain) {
                    let mut addr_chain = AddressChain::External;
                    if raw >= external_pk_list_len {
                        raw -= external_pk_list_len;
                        addr_chain = AddressChain::Internal;
                    }
                    (raw, addr_chain)
                };

                let op = OutPoint {
                    txid: txid.clone().into(),
                    vout: output_index as u32,
                };

                if output.script_pubkey.is_p2pkh() && account.address_type == AccountAddressType::P2PKH {
                    // TODO(evg): use correct index
                    for pk_index in 0..joined.len() {
                        let pk = &joined[pk_index];
                        let script = account.script_from_pk(pk);
                        let expected = &script.to_bytes();
                        if actual == expected {
                            let cache = get_pk_index(pk_index);
                            let key_path = KeyPath::new(cache.1, cache.0 as u32);

                            let utxo = Utxo::new(output.value, key_path, op,
                                                 account_index as u32, script, AccountAddressType::P2PKH);

                            account.grab_utxo(utxo.clone());
                            self.op_to_utxo.insert(op, utxo);
                        }
                    }
                }

                if output.script_pubkey.is_p2sh() && account.address_type == AccountAddressType::P2SHWH {
                    for pk_index in 0..joined.len() {
                        let pk = &joined[pk_index];
                        let script = account.script_from_pk(pk);
                        let expected = &script.to_bytes();
                        if actual == expected {
                            let cache = get_pk_index(pk_index);
                            let key_path = KeyPath::new(cache.1, cache.0 as u32);

                            let utxo = Utxo::new(output.value, key_path, op,
                                                 account_index as u32, script, AccountAddressType::P2SHWH);

                            account.grab_utxo(utxo.clone());
                            self.op_to_utxo.insert(op, utxo);
                        }
                    }
                }

                if output.script_pubkey.is_v0_p2wpkh() && account.address_type == AccountAddressType::P2WKH {
                    for pk_index in 0..joined.len() {
                        let pk = &joined[pk_index];
                        let script = account.script_from_pk(pk);
                        let expected = &script.to_bytes();
                        if actual == expected {
                            let cache = get_pk_index(pk_index);
                            let key_path = KeyPath::new(cache.1, cache.0 as u32);

                            let utxo = Utxo::new(output.value, key_path, op,
                                                 account_index as u32, script, AccountAddressType::P2WKH);

                            account.grab_utxo(utxo.clone());
                            self.op_to_utxo.insert(op, utxo);
                        }
                    }
                }
            }
        }
    }

    // ZMQ support
    pub fn process_wire_block(&mut self, block: WireBlock) {
        // TODO(evg): avoid redundant to_hex, from_hex methods
        for tx in block.txdata {
            self.process_tx(&TransactionId::from_str(&tx.txid().be_hex_string()).unwrap(), &tx);
        }

        // TODO(evg): update last seen block
    }

    pub fn process_block(&mut self, block_height: usize, block: &Block<TransactionId>) {
        for txid in &block.tx {
            let tx_hex = self.client.get_raw_transaction_serialized(&txid)
                .unwrap()
                .unwrap();
            let tx: BitcoinTransaction = BitcoinTransaction::from(tx_hex);
            self.process_tx(&txid, &tx);
        }
        // TODO(evg): if block_height > self.last_seen_block_height?
        self.last_seen_block_height = block_height;
        let mut buff = [0u8; 4];
        BigEndian::write_u32(&mut buff, block_height as u32);
        self.db.write().unwrap().put(LAST_SEEN_BLOCK_HEIGHT, &buff).unwrap();
    }

    pub fn process_block_range(&mut self, left: usize, right: usize) {
        for i in left..right+1 {
            let block_hash = self.client.get_block_hash(i as u32)
                .unwrap()
                .unwrap();

            let block = self.client.get_block(&block_hash)
                .unwrap()
                .unwrap();

            self.process_block(i, &block);
        }
    }

    // TODO(evg): impl error handling
    /// Initial sync with blockchain
    pub fn sync_with_blockchain(&mut self) {
        let block_height = self.client.get_block_count()
            .unwrap()
            .unwrap()
            .as_i64();

        self.process_block_range(1, block_height as usize);
    }

    /// Sync from last seen(processed) block
    pub fn sync_with_tip(&mut self) {
        let block_height = self.client.get_block_count()
            .unwrap()
            .unwrap()
            .as_i64();

        let start_from = self.last_seen_block_height + 1;
        self.process_block_range(start_from, block_height as usize);
    }
}