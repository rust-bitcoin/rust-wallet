//
// Copyright 2018-2019 Tamas Blummer
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
//! Accounts compatible with BIP32, BIP39, BIP44, BIP49, BIP84
//!

use std::sync::Arc;

use bitcoin::{Address, blockdata::{
    opcodes::all,
    transaction::{SigHashType, TxOut},
}, blockdata::script::Builder, network::constants::Network, OutPoint, PublicKey, Script, Transaction, util::bip143, util::bip32::{ChildNumber, ExtendedPrivKey}, PrivateKey};
use bitcoin_hashes::{Hash, hash160};

use context::SecpContext;
use error::WalletError;
use bitcoin::util::bip32::ExtendedPubKey;
use crate::mnemonic::Mnemonic;
use rand::{thread_rng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};
use crypto::hmac::Hmac;
use crypto::sha2::Sha512;
use crypto::pbkdf2::pbkdf2;
use std::collections::HashMap;

/// chose your security level
#[derive(Copy, Clone)]
pub enum MasterKeyEntropy {
    Low = 16,
    Recommended = 32,
    Paranoid = 64
}

/// A masterAccount is the root of an account hierarchy
pub struct MasterAccount {
    master_public: ExtendedPubKey,
    encrypted: Vec<u8>,
    accounts: HashMap<(u32, u32), Account>,
    birth: u64
}

impl MasterAccount {
    /// create a new random master account
    /// the information that leads to private key is stored encrypted with passphrase
    /// and the optional pd_passphrase (pd for plausible deniability)
    pub fn new (entropy: MasterKeyEntropy, network: Network, passphrase: &str, pd_passphrase: Option<&str>) -> Result<MasterAccount, WalletError> {
        let context = SecpContext::new();
        let mut random = vec!(0u8; entropy as usize);
        let mut rng = thread_rng();
        rng.fill_bytes(random.as_mut_slice());
        let mnemonic = Mnemonic::new(&random)?;
        let encrypted = mnemonic.encrypt(passphrase)?;
        let seed = Seed::new(&mnemonic, pd_passphrase);
        let master_key = context.master_private_key(network, &seed)?;
        let public_master_key = context.extended_public_from_private(&master_key);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Ok(MasterAccount { master_public: public_master_key, encrypted, accounts: HashMap::new(), birth: now})
    }

    /// Restore from encrypted store
    pub fn from_encrypted(encrypted: &[u8], public_master_key: ExtendedPubKey, birth: u64) -> MasterAccount {
        let encrypted = encrypted.to_vec();
        MasterAccount { master_public: public_master_key, encrypted, accounts: HashMap::new(), birth }
    }

    /// A watch only master. You will not be able to sign with this.
    pub fn watch_only(public_master_key: ExtendedPubKey, birth: u64) -> MasterAccount {
        MasterAccount { master_public: public_master_key, encrypted: Vec::new(), accounts: HashMap::new(), birth }
    }

    /// Restore from mnemonic
    pub fn from_mnemonic(mnemonic: &Mnemonic, birth: u64, network: Network, passphrase: &str, pd_passphrase: Option<&str>) -> Result<MasterAccount, WalletError> {
        let context = SecpContext::new();
        let encrypted = mnemonic.encrypt(passphrase)?;
        let seed = Seed::new(&mnemonic, pd_passphrase);
        let master_key = context.master_private_key(network, &seed)?;
        let public_master_key = context.extended_public_from_private(&master_key);
        Ok(MasterAccount { master_public: public_master_key, encrypted, accounts: HashMap::new(), birth })
    }

    /// get the mnemonic (human readable) representation of the master key
    pub fn mnemonic (&self, passphrase: &str) -> Result<Mnemonic, WalletError> {
        Ok(Mnemonic::decrypt(&self.encrypted, passphrase)?)
    }

    pub fn master_public (&self) ->&ExtendedPubKey {
        &self.master_public
    }

    pub fn encrypted(&self) -> &Vec<u8> {
        &self.encrypted
    }

    pub fn birth (&self) -> u64 {
        self.birth
    }

    pub fn get(&self, account: (u32, u32)) -> Option<&Account> {
        self.accounts.get(&account)
    }

    pub fn get_mut(&mut self, account: (u32, u32)) -> Option<&mut Account> {
        self.accounts.get_mut(&account)
    }

    pub fn accounts(&self) -> &HashMap<(u32, u32), Account> {
        &self.accounts
    }

    pub fn get_scripts<'a>(&'a self) -> impl Iterator<Item=(Script, KeyDerivation)> + 'a {
        self.accounts.iter().flat_map(
            |((an, sub), a)|
                a.get_scripts().map(move |(kix, s, tweak)|
                    (s, KeyDerivation{ account: *an, sub: *sub, kix, tweak})))
    }

    pub fn add_account(&mut self, account: Account) {
        self.accounts.insert((account.account_number, account.sub_account_number), account);
    }

    pub fn sign<R>(&self, transaction: &mut Transaction, hash_type: SigHashType, resolver: &R, unlocker: &mut Unlocker) -> Result<usize, WalletError>
        where R: Fn(&OutPoint) -> Option<TxOut> {
        let mut n_signatures = 0;
        for (_, a) in self.accounts.iter() {
            n_signatures += a.sign(transaction, hash_type, resolver, unlocker)?;
        }
        Ok(n_signatures)
    }
}

/// calculator of private keys
pub struct Unlocker {
    master_private: ExtendedPrivKey,
    network: Network,
    context: SecpContext,
    cached: HashMap<AccountAddressType,
        (ExtendedPrivKey, HashMap<u32,
            (ExtendedPrivKey, HashMap<u32,
                (ExtendedPrivKey, HashMap<u32, ExtendedPrivKey>)>)>)>,
}

impl Unlocker {
    /// decrypt encrypted seed of a master account
    /// check result if master_public is provided
    pub fn new (encrypted: &[u8], passphrase: &str, pd_passphrase: Option<&str>, network: Network, master_public: Option<&ExtendedPubKey>) -> Result<Unlocker, WalletError>{
        let mnemonic = Mnemonic::decrypt (encrypted, passphrase)?;
        let context = SecpContext::new();
        let master_private = context.master_private_key(network, &Seed::new(&mnemonic, pd_passphrase))?;
        if let Some(master_public) = master_public {
            if network != master_public.network {
                return Err(WalletError::Network);
            }
            if context.extended_public_from_private(&master_private) != *master_public {
                return Err(WalletError::Passphrase);
            }
        }
        Ok(Unlocker{master_private, network, context, cached: HashMap::new()})
    }

    pub fn master_private (&self) -> &ExtendedPrivKey {
        &self.master_private
    }

    pub fn sub_account_key(&mut self, address_type: AccountAddressType, account: u32, sub_account: u32) -> Result<ExtendedPrivKey, WalletError> {
        let by_purpose = self.cached.entry(address_type).or_insert(
            (
                self.context.private_child(&self.master_private, ChildNumber::Hardened { index: address_type.as_u32() })?
                , HashMap::new()));
        let coin_type = match self.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Regtest => 1
        };
        let by_coin_type = by_purpose.1.entry(coin_type).or_insert(
            (
                self.context.private_child(&by_purpose.0, ChildNumber::Hardened { index: coin_type })?
                ,HashMap::new()));
        let by_account = by_coin_type.1.entry(account).or_insert(
            (self.context.private_child(&by_coin_type.0, ChildNumber::Hardened { index: account })?, HashMap::new()));
        Ok(self.context.private_child(&by_account.0, ChildNumber::Normal { index: sub_account })?)
    }

    pub fn unlock (&mut self, address_type: AccountAddressType, account: u32, sub_account: u32, index: u32, tweak: Option<Vec<u8>>) -> Result<PrivateKey, WalletError> {
        let sub_account_key = self.sub_account_key(address_type, account, sub_account)?;
        let mut key = self.context.private_child(&sub_account_key, ChildNumber::Normal { index: index })?.private_key;
        if let Some(tweak) = tweak {
            self.context.tweak_add(&mut key, tweak.as_slice())?;
        }
        Ok(key)
    }
}

/// Key derivation detail information
/// coordinates of a key as defined in BIP32 and BIP44
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyDerivation {
    /// m / purpose' / coin_type' / account' / sub / kix
    pub account: u32,
    /// m / purpose' / coin_type' / account' / sub / kix
    pub sub: u32,
    /// m / purpose' / coin_type' / account' / sub / kix
    pub kix: u32,
    /// optional additive tweak to private key
    pub tweak: Option<Vec<u8>>
}

/// Address type an account is using
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum AccountAddressType {
    /// legacy pay to public key hash (BIP44)
    P2PKH,
    /// transitional segwit pay to public key hash in legacy format (BIP49)
    P2SHWPKH,
    /// native segwit pay to public key hash in bech format (BIP84)
    P2WPKH,
    /// native segwit pay to script
    /// do not use 44, 49 or 84 for this parameter, to avoid confusion with above types
    /// Only supports scripts that can be spent with following witness:
    /// <signature> <scriptCode>
    P2WSH(u32),
}

impl AccountAddressType {
    pub fn as_u32 (&self) -> u32 {
        match self {
            AccountAddressType::P2PKH => 44,
            AccountAddressType::P2SHWPKH => 49,
            AccountAddressType::P2WPKH => 84,
            AccountAddressType::P2WSH(n) => *n
        }
    }

    pub fn from_u32(n: u32) -> AccountAddressType {
        match n {
            44 => AccountAddressType::P2PKH,
            49 => AccountAddressType::P2SHWPKH,
            84 => AccountAddressType::P2WPKH,
            n => AccountAddressType::P2WSH(n)
        }
    }
}

pub struct Account {
    address_type: AccountAddressType,
    account_number: u32,
    sub_account_number: u32,
    context: Arc<SecpContext>,
    master_public: ExtendedPubKey,
    instantiated: Vec<InstantiatedKey>,
    next: u32,
    look_ahead: u32,
    network: Network,
}

impl Account {
    pub fn new (unlocker: &mut Unlocker, address_type: AccountAddressType, account_number: u32, sub_account_number: u32, look_ahead: u32) -> Result<Account, WalletError> {
        let context = Arc::new(SecpContext::new());
        let master_private = unlocker.sub_account_key(address_type, account_number, sub_account_number)?;
        let pubic_key = context.extended_public_from_private(&master_private);
        let mut sub = Account {
            address_type, account_number, sub_account_number, context,
            master_public: pubic_key, instantiated: Vec::new(), next: 0, look_ahead, network: pubic_key.network
        };
        sub.do_look_ahead(0)?;
        Ok(sub)
    }

    pub fn new_from_storage(address_type: AccountAddressType, account_number: u32, sub_account_number: u32,
                            master_public: ExtendedPubKey, instantiated: Vec<InstantiatedKey>,
                            next: u32, look_ahead: u32, network: Network) -> Account {
        let context = Arc::new(SecpContext::new());
        Account {
            address_type, account_number, sub_account_number, context, master_public, instantiated, next, look_ahead, network
        }
    }

    pub fn address_type (&self) -> AccountAddressType {
        self.address_type
    }

    pub fn account_number(&self) -> u32 {
        self.account_number
    }

    pub fn sub_account_number(&self) -> u32 {
        self.sub_account_number
    }

    pub fn master_public(&self) -> &ExtendedPubKey {
        &self.master_public
    }

    pub fn next(&self) -> u32 {
        self.next
    }

    pub fn look_ahead(&self) -> u32 {
        self.look_ahead
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn instantiated(&self) -> &Vec<InstantiatedKey> {
        &self.instantiated
    }

    /// look ahead from last seen
    pub fn do_look_ahead(&mut self, seen: u32) -> Result<Vec<(u32, Script)>, WalletError> {
        use std::cmp::max;

        self.next = max(self.next, seen + 1);

        let have = self.instantiated.len() as u32;
        let need = max(seen + self.look_ahead, have) - have;
        let mut new = Vec::new();
        for i in 0..need {
            new.push((have + i, self.instantiate_more()?.script_pubkey.clone()));
        }
        Ok(new)
    }

    fn instantiate_more (&mut self) -> Result<&InstantiatedKey, WalletError> {
        let instantiated = InstantiatedKey::new_from_extended_key(self.address_type, self.network,
                                                                  self.instantiated.len() as u32,
                                                                  &self.master_public, self.context.clone())?;
        let len = self.instantiated.len();
        self.instantiated.push(instantiated);
        Ok(&self.instantiated[len])
    }

    /// create a new key
    pub fn next_key(&mut self) -> Result<&InstantiatedKey, WalletError> {
        self.instantiate_more()?;
        let key = &self.instantiated[self.next as usize];
        self.next += 1;
        Ok(&key)
    }

    /// get a previously instantiated key
    pub fn get_key(&self, kix: u32) -> Option<&InstantiatedKey> {
        self.instantiated.get(kix as usize)
    }

    pub fn add_script_key(&mut self, pk: PublicKey, script_code: Script, tweak: Option<&[u8]>) -> Result<u32, WalletError> {
        match self.address_type {
            AccountAddressType::P2WSH(_) => {}
            _ => return Err(WalletError::Unsupported("add_script_key can only be used for P2WSH accounts"))
        }
        let index = self.instantiated.len() as u32;
        let instantiated = InstantiatedKey::new(self.address_type, self.network, pk,
                                                tweak, index, Some(script_code), self.context.clone())?;
        self.instantiated.push(instantiated);
        Ok((self.instantiated.len() - 1) as u32)
    }

    pub fn used(&self) -> usize {
        self.next as usize
    }

    // get all pubkey scripts of this account
    pub fn get_scripts<'a>(&'a self) -> impl Iterator<Item=(u32, Script, Option<Vec<u8>>)> + 'a {
        self.instantiated.iter().enumerate().map(|(kix, i)| (kix as u32, i.script_pubkey.clone(), i.tweak.clone()))
    }

    /// sign a transaction with keys in this account works for types except P2WSH
    pub fn sign<R>(&self, transaction: &mut Transaction, hash_type: SigHashType, resolver: R, unlocker: &mut Unlocker) -> Result<usize, WalletError>
        where R: Fn(&OutPoint) -> Option<TxOut> {
        let mut signed = 0;
        let txclone = transaction.clone();
        let mut bip143hasher: Option<bip143::SighashComponents> = None;
        for (ix, input) in transaction.input.iter_mut().enumerate() {
            if let Some(spend) = resolver(&input.previous_output) {
                if let Some(instantiated) =
                self.instantiated.iter().find(|i| i.script_pubkey == spend.script_pubkey) {
                    let pk = unlocker.unlock(self.address_type, self.account_number, self.sub_account_number, instantiated.index, instantiated.tweak.clone())?;
                    match self.address_type {
                        AccountAddressType::P2PKH => {
                            let sighash = txclone.signature_hash(ix, &instantiated.address.script_pubkey(), hash_type.as_u32());
                            let signature = self.context.sign(&sighash[..], &pk)?.serialize_der();
                            let mut with_hashtype = signature.to_vec();
                            with_hashtype.push(hash_type.as_u32() as u8);
                            input.script_sig = Builder::new()
                                .push_slice(with_hashtype.as_slice())
                                .push_slice(instantiated.public.to_bytes().as_slice()).into_script();
                            input.witness.clear();
                            signed += 1;
                        }
                        AccountAddressType::P2WPKH => {
                            if hash_type.as_u32() & SigHashType::All.as_u32() == 0 {
                                return Err(WalletError::Unsupported("can only sig all inputs for now"));
                            }
                            input.script_sig = Script::new();
                            let hasher = bip143hasher.unwrap_or(bip143::SighashComponents::new(&txclone));
                            let sighash = hasher.sighash_all(&txclone.input[ix], &instantiated.script_code, spend.value);
                            bip143hasher = Some(hasher);
                            let signature = self.context.sign(&sighash[..], &pk)?.serialize_der();
                            let mut with_hashtype = signature.to_vec();
                            with_hashtype.push(hash_type.as_u32() as u8);
                            input.witness.clear();
                            input.witness.push(with_hashtype);
                            input.witness.push(instantiated.public.to_bytes());
                            signed += 1;
                        }
                        AccountAddressType::P2SHWPKH => {
                            if hash_type.as_u32() & SigHashType::All.as_u32() == 0 {
                                return Err(WalletError::Unsupported("can only sig all inputs for now"));
                            }
                            input.script_sig = Builder::new().push_slice(&Builder::new()
                                .push_int(0)
                                .push_slice(&hash160::Hash::hash(instantiated.public.to_bytes().as_slice())[..])
                                .into_script()[..]).into_script();
                            let hasher = bip143hasher.unwrap_or(bip143::SighashComponents::new(&txclone));
                            let sighash = hasher.sighash_all(&txclone.input[ix], &instantiated.script_code, spend.value);
                            bip143hasher = Some(hasher);
                            let signature = self.context.sign(&sighash[..], &pk)?.serialize_der();
                            let mut with_hashtype = signature.to_vec();
                            with_hashtype.push(hash_type.as_u32() as u8);
                            input.witness.clear();
                            input.witness.push(with_hashtype);
                            input.witness.push(instantiated.public.to_bytes());
                            signed += 1;
                        }
                        AccountAddressType::P2WSH(_) => {
                            if hash_type.as_u32() & SigHashType::All.as_u32() == 0 {
                                return Err(WalletError::Unsupported("can only sig all inputs for now"));
                            }
                            input.script_sig = Script::new();
                            let hasher = bip143hasher.unwrap_or(bip143::SighashComponents::new(&txclone));
                            let sighash = hasher.sighash_all(&txclone.input[ix], &instantiated.script_code, spend.value);
                            bip143hasher = Some(hasher);
                            let signature = self.context.sign(&sighash[..], &pk)?.serialize_der();
                            let mut with_hashtype = signature.to_vec();
                            with_hashtype.push(hash_type.as_u32() as u8);
                            input.witness.clear();
                            input.witness.push(with_hashtype);
                            input.witness.push(instantiated.script_code.to_bytes());
                            signed += 1;
                        }
                    }
                }
            }
        }
        Ok(signed)
    }
}

/// instantiated key of an account
#[derive(Clone, Serialize, Deserialize)]
pub struct InstantiatedKey {
    pub index: u32,
    pub public: PublicKey,
    pub script_code: Script,
    pub address: Address,
    pub script_pubkey: Script,
    pub tweak: Option<Vec<u8>>
}


impl InstantiatedKey {
    pub fn new_from_extended_key(address_type: AccountAddressType, network: Network, index: u32, ek: &ExtendedPubKey, context: Arc<SecpContext>) -> Result<InstantiatedKey, WalletError> {
        return Self::new(address_type, network, context.public_child(&ek, ChildNumber::Normal {index})?.public_key, None, index, None, context);
    }

    pub fn new(address_type: AccountAddressType, network: Network, mut public: PublicKey, tweak: Option<&[u8]>, index: u32, script_code: Option<Script>, context: Arc<SecpContext>) -> Result<InstantiatedKey, WalletError> {
        if let Some(tweak) = tweak {
            context.tweak_exp_add(&mut public, tweak)?;
        }
        let (script_code, address) = match address_type {
            AccountAddressType::P2PKH => (Script::new(), Address::p2pkh(&public, network)),
            AccountAddressType::P2SHWPKH => (
                Builder::new()
                    .push_opcode(all::OP_DUP)
                    .push_opcode(all::OP_HASH160)
                    .push_slice(&hash160::Hash::hash(public.to_bytes().as_slice())[..])
                    .push_opcode(all::OP_EQUALVERIFY)
                    .push_opcode(all::OP_CHECKSIG)
                    .into_script(),
                Address::p2shwpkh(&public, network)),
            AccountAddressType::P2WPKH => (
                Builder::new()
                    .push_opcode(all::OP_DUP)
                    .push_opcode(all::OP_HASH160)
                    .push_slice(&hash160::Hash::hash(public.to_bytes().as_slice())[..])
                    .push_opcode(all::OP_EQUALVERIFY)
                    .push_opcode(all::OP_CHECKSIG)
                    .into_script(),
                Address::p2wpkh(&public, network)),
            AccountAddressType::P2WSH(_) => {
                if let Some(ref script_code) = script_code {
                    (script_code.clone(), Address::p2wsh(script_code, network))
                } else {
                    return Err(WalletError::Unsupported("need script_code for P2WSH address"));
                }
            }
        };
        let script_pubkey = address.script_pubkey();
        Ok(InstantiatedKey { index, public, script_code, address, script_pubkey, tweak: tweak.map(|t|t.to_vec()) })
    }
}

/// seed of the master key
pub struct Seed(pub Vec<u8>);

impl Seed {
    /// create a seed from mnemonic
    /// with optional passphrase for plausible deniability see BIP39
    pub fn new(mnemonic: &Mnemonic, pd_passphrase: Option<&str>) -> Seed {
        let mut mac = Hmac::new(Sha512::new(), mnemonic.to_string().as_bytes());
        let mut output = [0u8; 64];
        let passphrase = "mnemonic".to_owned() + pd_passphrase.unwrap_or("");
        pbkdf2(&mut mac, passphrase.as_bytes(), 2048, &mut output);
        Seed(output.to_vec())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use bitcoin::blockdata::opcodes::all;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
    use bitcoin_hashes::sha256d;

    use super::*;

    use std::fs::File;
    use std::path::PathBuf;
    use std::io::Read;
    use bitcoin::network::constants::Network;
    use bitcoin::util::bip32::ChildNumber;

    use serde_json::{Value};
    use hex::decode;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn test_pkh() {
        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, PASSPHRASE, None).unwrap();
        let mut unlocker = Unlocker::new(master.encrypted(), PASSPHRASE, None, Network::Bitcoin, None).unwrap();
        let account = Account::new(&mut unlocker, AccountAddressType::P2PKH, 0, 0, 10).unwrap();
        master.add_account(account);
        let account = master.get_mut((0,0)).unwrap();
        let i = account.next_key().unwrap();
        let source = i.address.clone();
        let target = i.address.clone();
        let input_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0xffffffff,
            version: 1,
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0xffffffff,
            version: 1,
        };

        let mut spent = HashMap::new();
        spent.insert(input_transaction.txid(), input_transaction.clone());

        assert_eq!(master.sign(&mut spending_transaction, SigHashType::All,
                               &(|_| Some(input_transaction.output[0].clone())), &mut unlocker).unwrap(), 1);

        spending_transaction.verify(|point|
            spent.get(&point.txid).and_then(|t| t.output.get(point.vout as usize).cloned())
        ).unwrap();
    }

    #[test]
    fn test_wpkh() {
        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, PASSPHRASE, None).unwrap();
        let mut unlocker = Unlocker::new(master.encrypted(), PASSPHRASE, None, Network::Bitcoin, None).unwrap();
        let account = Account::new(&mut unlocker, AccountAddressType::P2WPKH, 0, 0, 10).unwrap();
        master.add_account(account);
        let account = master.get_mut((0,0)).unwrap();
        let i = account.next_key().unwrap();
        let source = i.address.clone();
        let target = i.address.clone();

        let input_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0x11000000,
            version: 1,
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0x11000000,
            version: 1,
        };

        let mut spent = HashMap::new();
        spent.insert(txid, input_transaction.clone());

        assert_eq!(master.sign(&mut spending_transaction, SigHashType::All,
                               &(|_| Some(input_transaction.output[0].clone())), &mut unlocker).unwrap(), 1);

        spending_transaction.verify(|point|
            spent.get(&point.txid).and_then(|t| t.output.get(point.vout as usize).cloned())
        ).unwrap();
    }

    #[test]
    fn test_shwpkh() {
        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, PASSPHRASE, None).unwrap();
        let mut unlocker = Unlocker::new(master.encrypted(), PASSPHRASE, None, Network::Bitcoin, None).unwrap();
        let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, 10).unwrap();
        master.add_account(account);
        let account = master.get_mut((0,0)).unwrap();
        let i = account.next_key().unwrap();
        let source = i.address.clone();
        let target = i.address.clone();

        let input_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0x11000000,
            version: 1,
        };

        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0x11000000,
            version: 1,
        };

        let mut spent = HashMap::new();
        spent.insert(txid, input_transaction.clone());

        assert_eq!(master.sign(&mut spending_transaction, SigHashType::All,
                               &(|_| Some(input_transaction.output[0].clone())), &mut unlocker).unwrap(), 1);

        spending_transaction.verify(|point|
            spent.get(&point.txid).and_then(|t| t.output.get(point.vout as usize).cloned())
        ).unwrap();
    }

    #[test]
    fn test_wsh() {

        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, PASSPHRASE, None).unwrap();
        let mut unlocker = Unlocker::new(master.encrypted(), PASSPHRASE, None, Network::Bitcoin, None).unwrap();
        let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, 10).unwrap();
        master.add_account(account);
        let account = Account::new(&mut unlocker, AccountAddressType::P2WSH(4711), 1, 0, 0).unwrap();
        master.add_account(account);

        let ctx = Arc::new(SecpContext::new());

        let mut pk;
        {
            let base_account = master.get_mut((0, 0)).unwrap();
            pk = base_account.next_key().unwrap().public;
        }
        ctx.tweak_exp_add(&mut pk, &[0x01; 32]).unwrap();

        {
            let account = master.get_mut((1, 0)).unwrap();
            let script_code = Builder::new()
                .push_slice(pk.to_bytes().as_slice())
                .push_opcode(all::OP_CHECKSIG)
                .into_script();
            account.add_script_key(pk, script_code, Some(&[0x01; 32])).unwrap();
        }


        let base_account = master.get((0, 0)).unwrap();
        let account = master.get((0,0)).unwrap();
        let source = base_account.get_key(0).unwrap().address.clone();
        let target = account.get_key(0).unwrap().address.clone();
        let input_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0xffffffff,
            version: 1,
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0xffffffff,
            version: 1,
        };

        let mut spent = HashMap::new();
        spent.insert(input_transaction.txid(), input_transaction.clone());

        assert_eq!(master.sign(
            &mut spending_transaction, SigHashType::All,
            &(|_| Some(input_transaction.output[0].clone())), &mut unlocker).unwrap(), 1);

        spending_transaction.verify(|point|
            spent.get(&point.txid).and_then(|t| t.output.get(point.vout as usize).cloned())
        ).unwrap();
    }

    #[test]
    fn crosscheck_with_hardware_wallet () {
        let words = "announce damage viable ticket engage curious yellow ten clock finish burden orient faculty rigid smile host offer affair suffer slogan mercy another switch park";
        let mnemonic = Mnemonic::from_str(words).unwrap();
        let master = MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();
        let mut unlocker = Unlocker::new(
            master.encrypted(), PASSPHRASE, None, Network::Bitcoin, Some(master.master_public())
        ).unwrap();
        let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, 10).unwrap();
        // this should be address of m/49'/0'/0'/0/0
        assert_eq!(account.get_key(0).unwrap().address.to_string(), "3L8V8mDQVUySGwCqiB2x8fdRRMGWyyF4YP");
        let account = Account::new(&mut unlocker, AccountAddressType::P2WPKH, 0, 0, 10).unwrap();
        // this should be address of m/84'/0'/0'/0/0
        assert_eq!(account.get_key(0).unwrap().address.to_string(), "bc1qlz2h9scgalmqj43d36f58dcxrrl7udu999gcp2");
    }

    #[test]
    fn bip32_tests () {
        let context = super::SecpContext::new();

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/BIP32.json");
        let mut file = File::open(d).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json: Value = serde_json::from_str(&data).unwrap();
        let tests = json.as_array().unwrap();
        for test in tests {
            let seed = Seed(decode(test["seed"].as_str().unwrap()).unwrap());
            let master_private = context.master_private_key(Network::Bitcoin, &seed).unwrap();
            assert_eq!(test["private"].as_str().unwrap(), master_private.to_string());
            assert_eq!(test["public"].as_str().unwrap(), context.extended_public_from_private(&master_private).to_string());
            for d in test["derived"].as_array().unwrap() {
                let mut key = master_private.clone();
                for l in d ["locator"].as_array().unwrap() {
                    let sequence = l ["sequence"].as_u64().unwrap();
                    let private = l ["private"].as_bool().unwrap();
                    let child = if private {
                        ChildNumber::Hardened{index:sequence as u32}
                    } else {
                        ChildNumber::Normal{index:sequence as u32}
                    };
                    key = context.private_child(&key.clone(), child).unwrap();
                }
                assert_eq!(d ["private"].as_str().unwrap(), key.to_string());
                assert_eq!(d ["public"].as_str().unwrap(), context.extended_public_from_private(&key).to_string());
            }
        }
    }
}
