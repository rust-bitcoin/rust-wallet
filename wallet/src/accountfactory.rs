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

    blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut},
    blockdata::script::{Script, Builder},
    blockdata::block::Block,

    network::constants::Network,
};
use secp256k1::{Secp256k1, PublicKey, Message};

use std::{
    error::Error,
    sync::{Arc, RwLock},
    collections::HashMap,
    str::FromStr,
};

use error::WalletError;
use mnemonic::Mnemonic;
use keyfactory::{KeyFactory, MasterKeyEntropy};
use account::{Account, AccountAddressType, Utxo, KeyPath, AddressChain};
use db::DB;
use interface::{Wallet, BlockChainIO};

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
    pub url:      String,
    pub user:     String,
    pub password: String,
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
pub struct LockGroup(Vec<OutPoint>);

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
    p2pkh_account: Account,
    p2shwh_account: Account,
    p2wkh_account: Account,
    #[allow(dead_code)]
    network: Network,

    // TODO(evg): bio
    bio: Box<BlockChainIO + Send>,

    last_seen_block_height: usize,
    op_to_utxo: HashMap<OutPoint, Utxo>,
    next_lock_id: LockId,
    locked_coins: LockGroupMap,
    db: Arc<RwLock<DB>>,
}

impl Wallet for AccountFactory {
    fn new_address(&mut self, address_type: AccountAddressType) -> Result<String, Box<Error>> {
        self.get_account_mut(address_type).new_address()
    }

    fn new_change_address(&mut self, address_type: AccountAddressType) -> Result<String, Box<Error>> {
        self.get_account_mut(address_type).new_change_address()
    }

    fn get_utxo_list(&self) -> Vec<Utxo> {
        let mut joined = Vec::new();
        for account in &[&self.p2pkh_account, &self.p2shwh_account, &self.p2wkh_account] {
            let account_utxo_list = &account.get_utxo_list();
            for (_, val) in *account_utxo_list {
                joined.push(val.clone());
            }
        }
        joined
    }

    fn wallet_balance(&self) -> u64 {
        let utxo_list = self.get_utxo_list();

        let mut balance: u64 = 0;
        for utxo in utxo_list {
            balance += utxo.value;
        }
        balance
    }

    fn unlock_coins(&mut self, lock_id: LockId) {
        self.locked_coins.unlock_group(lock_id);
    }

    fn send_coins(&mut self, addr_str: String, amt: u64, lock_coins: bool, witness_only: bool, submit: bool) -> Result<(Transaction, LockId), Box<Error>> {
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

        let tx = self.make_tx(subset.clone(), addr_str, amt, submit)?;
        if lock_coins {
            let lock_group = LockGroup(subset);
            self.locked_coins.lock_group(self.next_lock_id.clone(), lock_group.clone());

            self.db.write().unwrap().put_lock_group(&self.next_lock_id, &lock_group);

            let rez = self.next_lock_id.clone();
            self.next_lock_id.incr();
            return Ok((tx, rez));
        };

        Ok((tx, LockId::new()))
    }

    // TODO(evg): add version, lock_time param?
    fn make_tx(&mut self, ops: Vec<OutPoint>, addr_str: String, amt: u64, submit: bool) -> Result<Transaction, Box<Error>> {
        let addr: Address = Address::from_str(&addr_str).unwrap();

        let mut tx = Transaction {
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
            let change_addr = self.get_account_mut(AccountAddressType::P2WKH).new_change_address().unwrap();
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

            let account = self.get_account((utxo.account_index as usize).into());

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

        if submit {
            self.bio.send_raw_transaction(&tx);
        }

        Ok(tx)
    }

    fn publish_tx(&self, tx: &Transaction) {
        self.bio.send_raw_transaction(tx);
    }

    /// Sync from last seen(processed) block
    fn sync_with_tip(&mut self) {
        let block_height = self.bio.get_block_count();

        let start_from = self.last_seen_block_height + 1;
        self.process_block_range(start_from, block_height as usize);
    }
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

    pub fn new_no_random (wc: WalletConfig, bio: Box<BlockChainIO + Send>) -> Result<AccountFactory, WalletError> {
        let (master_key, mnemonic, encrypted, _) =
            KeyFactory::new_master_private_key_no_random (
                wc.entropy,
                wc.network,
                &wc.passphrase,
                &wc.salt,
            )?;

        let db = DB::new(wc.db_path);
        let last_seen_block_height = db.get_last_seen_block_height();
        let op_to_utxo = db.get_utxo_map();
        let db = Arc::new(RwLock::new(db));

        let p2pkh_account = AccountFactory::new_account(
            master_key,
            0,
            AccountAddressType::P2PKH,
            Network::Regtest,
            Arc::clone(&db),
        );

        let p2shwh_account = AccountFactory::new_account(
            master_key,
            0,
            AccountAddressType::P2SHWH,
            Network::Regtest,
            Arc::clone(&db),
        );

        let p2wkh_account = AccountFactory::new_account(
            master_key,
            0,
            AccountAddressType::P2WKH,
            Network::Regtest,
            Arc::clone(&db),
        );

        let mut ac = AccountFactory{
            master_key,
            mnemonic,
            encrypted,
            p2pkh_account,
            p2shwh_account,
            p2wkh_account,
            network: wc.network,
            bio,
            last_seen_block_height,
            op_to_utxo,
            next_lock_id: LockId::new(),
            locked_coins: LockGroupMap::new(),
            db,
        };
        let op_to_utxo = ac.op_to_utxo.clone();
        for (_, val) in &op_to_utxo {
            ac.get_account_mut(val.addr_type.clone()).utxo_list.insert(val.out_point, val.clone());
        }

        let external_secret_key_list = ac.db.read().unwrap().get_external_secret_key_list();
        for (key_helper, sk) in external_secret_key_list {
            ac.get_account_mut(key_helper.addr_type.clone()).external_sk_list.push(sk);
        }

        let external_public_key_list = ac.db.read().unwrap().get_external_public_key_list();
        for (key_helper, pk) in external_public_key_list {
            ac.get_account_mut(key_helper.addr_type.clone()).external_pk_list.push(pk);
        }

        let internal_secret_key_list = ac.db.read().unwrap().get_internal_secret_key_list();
        for (key_helper, sk) in internal_secret_key_list {
            ac.get_account_mut(key_helper.addr_type.clone()).internal_sk_list.push(sk);
        }

        let internal_public_key_list = ac.db.read().unwrap().get_internal_public_key_list();
        for (key_helper, pk) in internal_public_key_list {
            ac.get_account_mut(key_helper.addr_type.clone()).internal_pk_list.push(pk);
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

    /// get a copy of the master private key
    pub fn master_private (&self) -> ExtendedPrivKey {
        self.master_key.clone()
    }

    /// get a copy of the master public key
    pub fn master_public (&self) -> ExtendedPubKey {
        KeyFactory::extended_public_from_private(&self.master_key)
    }

    pub fn mnemonic (&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn encrypted (&self) -> Vec<u8> {
        self.encrypted.clone()
    }

    /// get an account
    pub fn extract_account_key(
        master_key: ExtendedPrivKey,
        account_number: u32,
        address_type: AccountAddressType,
    ) -> Result<ExtendedPrivKey, WalletError> {

        let mut key = match address_type {
            AccountAddressType::P2PKH  => KeyFactory::private_child(
                &master_key,
                ChildNumber::Hardened{index: 44},
            )?,
            AccountAddressType::P2SHWH => KeyFactory::private_child(
                &master_key,
                ChildNumber::Hardened{index: 49},
            )?,
            AccountAddressType::P2WKH  => KeyFactory::private_child(
                &master_key,
                ChildNumber::Hardened{index: 84},
            )?,
        };

        key = match key.network {
            Network::Bitcoin => KeyFactory::private_child(&key, ChildNumber::Hardened{index: 0})?,
            Network::Testnet => KeyFactory::private_child(&key, ChildNumber::Hardened{index: 1})?,
            // TODO(evg): `ChildNumber::Hardened{index: 2}` is it correct?
            Network::Regtest => KeyFactory::private_child(&key, ChildNumber::Hardened{index: 2})?,
        };

        key = KeyFactory::private_child(&key, ChildNumber::Hardened{index: account_number})?;

        Ok(key)
    }

    fn new_account(
        master_key: ExtendedPrivKey,
        account_number: u32,
        address_type: AccountAddressType,
        network: Network,
        db: Arc<RwLock<DB>>,
    ) -> Account {
        let key = AccountFactory::extract_account_key(
            master_key,
            account_number,
            address_type.clone(),
        ).unwrap();

        Account::new(
            key,
            address_type,
            network,
            Arc::clone(&db),
        )
    }

    fn get_account(&self, address_type: AccountAddressType) -> &Account {
        match address_type {
            AccountAddressType::P2PKH  => &self.p2pkh_account,
            AccountAddressType::P2SHWH => &self.p2shwh_account,
            AccountAddressType::P2WKH  => &self.p2wkh_account,
        }
    }

    pub fn get_account_mut(&mut self, address_type: AccountAddressType) -> &mut Account {
        match address_type {
            AccountAddressType::P2PKH  => &mut self.p2pkh_account,
            AccountAddressType::P2SHWH => &mut self.p2shwh_account,
            AccountAddressType::P2WKH  => &mut self.p2wkh_account,
        }
    }

    pub fn process_tx(&mut self, tx: &Transaction) {
        let account_list = &mut [&mut self.p2pkh_account, &mut self.p2shwh_account, &mut self.p2wkh_account];

        for input_index in 0..tx.input.len() {
            let input = &tx.input[input_index];
            if self.op_to_utxo.contains_key(&input.previous_output) {
                {
                    // remove from account utxo map
                    let utxo = self.op_to_utxo.get(&input.previous_output).unwrap();
                    let mut acc = &mut account_list[usize::from(utxo.addr_type.clone())];
                    let mut utxo_map = &mut acc.utxo_list;
                    utxo_map.remove(&input.previous_output).unwrap();

                    self.db.write().unwrap().delete_utxo(&utxo.out_point);
                }

                // remove from account_factory utxo_map
                self.op_to_utxo.remove(&input.previous_output).unwrap();
            }
        }
        for account_index in 0..account_list.len() {
            let mut account = &mut account_list[account_index];

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
                    txid: tx.txid(),
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

    fn process_block(&mut self, block_height: usize, block: &Block) {
        for tx in &block.txdata {
            self.process_tx(&tx);
        }
        // TODO(evg): if block_height > self.last_seen_block_height?
        self.last_seen_block_height = block_height;

        self.db.write().unwrap().put_last_seen_block_height(block_height as u32);
    }

    fn process_block_range(&mut self, left: usize, right: usize) {
        for i in left..right+1 {
            let block_hash = self.bio.get_block_hash(i as u32);
            let block = self.bio.get_block(&block_hash);
            self.process_block(i, &block);
        }
    }
}