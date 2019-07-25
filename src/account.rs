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
//! TREZOR compatible accounts (BIP44, BIP49, BIP84)
//!
use bitcoin::{
    Address, Transaction, PrivateKey, Script, PublicKey, OutPoint,
    blockdata::{
        opcodes::all,
        transaction::{TxOut, SigHashType}
    },
    blockdata::script::Builder,
    util::bip32::{ExtendedPrivKey,ChildNumber},
    util::bip143,
    network::constants::Network
};
use bitcoin_hashes::{Hash, hash160};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use context::SecpContext;
use error::WalletError;

/// Address type an account is using
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum AccountAddressType {
    /// legacy pay to public key hash
    P2PKH,
    /// transitional segwit pay to public key hash in legacy format
    P2SHWPKH,
    /// native segwit pay to public key hash in bech format
    P2WPKH,
    /// native segwit pay to script
    /// do not use 44, 49 or 84 for this parameter, to avoid confusion with above types
    P2WSH(u32)
}

/// a TREZOR compatible account
pub struct Account {
    address_type: AccountAddressType,
    key: ExtendedPrivKey,
    context: Arc<SecpContext>,
    birth: u64, // seconds in unix epoch
    network: Network,
    pub receive: SubAccount,
    pub change: SubAccount
}

impl Account {
    /// create a new account
    pub fn new (context: Arc<SecpContext>, key: ExtendedPrivKey, address_type: AccountAddressType, birth: Option<u64>, network: Network) -> Result<Account, WalletError> {
        let birth = birth.unwrap_or(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

        let receive = SubAccount{
            context: context.clone(), address_type, birth, next:0,
            key: context.private_child(&key, ChildNumber::Normal{index:0})?,
            instantiated: Vec::new(),
            network
        };
        let change = SubAccount{
            context: context.clone(), address_type, birth, next:0,
            key: context.private_child(&key, ChildNumber::Normal{index:1})?,
            instantiated: Vec::new(),
            network
        };

        Ok(Account { context, key: key, address_type, birth, receive, change, network })
    }

    /// sign a transaction with keys in this account
    pub fn sign<R> (&self, transaction: &mut Transaction, hash_type: SigHashType, resolver: R) -> Result<usize, WalletError>
        where R: Fn(&OutPoint) -> Option<TxOut> + Copy {
        let a = self.receive.sign(transaction, hash_type, resolver).unwrap();
        let b = self.change.sign(transaction, hash_type, resolver).unwrap();
        Ok (a + b)
    }

    pub fn birth (&self) -> u64 {
        self.birth
    }
}

pub struct SubAccount {
    address_type: AccountAddressType,
    context: Arc<SecpContext>,
    key: ExtendedPrivKey,
    instantiated: Vec<(u32, PrivateKey, PublicKey, Address)>,
    birth: u64,
    network: Network,
    next: u32
}

impl SubAccount {
    /// create a new key
    pub fn new_key(&mut self, ix: u32) -> Result<PrivateKey,WalletError> {
        if let Some((_, pk, public, _)) = self.instantiated.iter().find(|(i,_, _, _)| ix == *i) {
            return Ok(pk.clone());
        }
        else {
            let pk = self.context.private_child(&self.key, ChildNumber::Normal { index: ix })?.private_key;
            let public = self.context.public_from_private(&pk);
            let address = match self.address_type {
                AccountAddressType::P2PKH => Address::p2pkh(&self.context.public_from_private(&pk), self.network),
                AccountAddressType::P2SHWPKH => Address::p2shwpkh(&self.context.public_from_private(&pk), self.network),
                AccountAddressType::P2WPKH => Address::p2wpkh(&self.context.public_from_private(&pk), self.network),
                AccountAddressType::P2WSH(_) => return Err(WalletError::Unsupported("use new_key_script instead"))
                };
            self.instantiated.push((ix, pk, public, address));
            Ok(pk)
        }
    }

    /// create a new key for a P2WSH account
    pub fn new_key_script<S>(&mut self, ix: u32, scripter: S) -> Result<PrivateKey,WalletError>
        where S: Fn(u32, &PublicKey) -> Script
    {
        if let Some((_, pk, public, _)) = self.instantiated.iter().find(|(i,_, _, _)| ix == *i) {
            return Ok(pk.clone());
        }
        else {
            let pk = self.context.private_child(&self.key, ChildNumber::Normal { index: ix })?.private_key;
            let public = self.context.public_from_private(&pk);
            let address = match self.address_type {
                AccountAddressType::P2WSH(n) => Address::p2wsh(&scripter(n, &public), self.network),
                _ => return Err(WalletError::Unsupported("use new_key instead"))
            };
            self.instantiated.push((ix, pk, public, address));
            Ok(pk)
        }
    }

    /// get a previously created private key for an index
    pub fn get_key(&self, ix: u32) -> Option<PrivateKey> {
        if let Some((_, pk, _, _)) = self.instantiated.iter().find(|(i,_, _, _)| ix == *i) {
            return Some(pk.clone());
        }
        None
    }

    /// get the address for an index, key for this index must have been created earlier
    pub fn get_address (&self, ix: u32) -> Option<Address> {
        if let Some((_, _, _, address)) = self.instantiated.iter().find(|(i,_, _, _)| ix == *i) {
            return Some(address.clone());
        }
        None
    }

    /// sign a transaction with keys in this account works for types except P2WSH
    pub fn sign<R> (&self, transaction: &mut Transaction, hash_type: SigHashType, resolver: R) -> Result<usize, WalletError>
        where R: Fn(&OutPoint) -> Option<TxOut> {
        let mut signed = 0;
        let txclone = transaction.clone();
        for (ix, input) in transaction.input.iter_mut().enumerate() {
            if let Some(spend) = resolver (&input.previous_output) {
                if let Some((_,pk,public,a)) = self.instantiated.iter().find(|(_,_,_,a)| a.script_pubkey() == spend.script_pubkey) {
                    match self.address_type {
                        AccountAddressType::P2PKH => {
                            let sighash = txclone.signature_hash(ix, &a.script_pubkey(), hash_type.as_u32());
                            let mut signature = self.context.sign(&sighash[..], pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.script_sig = Builder::new()
                                .push_slice(signature.as_slice())
                                .push_slice(public.to_bytes().as_slice()).into_script();
                            signed += 1;
                        },
                        AccountAddressType::P2WPKH => {
                            if hash_type.as_u32() & SigHashType::All.as_u32() == 0 {
                                return Err(WalletError::Unsupported("can only sig all inputs for now"));
                            }
                            input.script_sig = Script::new();
                            let script_code = Builder::new()
                                .push_opcode(all::OP_DUP)
                                .push_opcode(all::OP_HASH160)
                                .push_slice(&hash160::Hash::hash(public.to_bytes().as_slice())[..])
                                .push_opcode(all::OP_EQUALVERIFY)
                                .push_opcode(all::OP_CHECKSIG)
                                .into_script();

                            let sighash = bip143::SighashComponents::new(&txclone).sighash_all(&txclone.input[ix], &script_code, spend.value);
                            let mut signature = self.context.sign(&sighash[..], pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.witness.push(signature);
                            input.witness.push(public.to_bytes());
                            signed += 1;
                        },
                        AccountAddressType::P2SHWPKH => {
                            if hash_type.as_u32() & SigHashType::All.as_u32() == 0 {
                                return Err(WalletError::Unsupported("can only sig all inputs for now"));
                            }
                            input.script_sig = Builder::new().push_slice(&Builder::new()
                                .push_int(0)
                                .push_slice(&hash160::Hash::hash(public.to_bytes().as_slice())[..])
                                .into_script()[..]).into_script();
                            let script_code = Builder::new()
                                .push_opcode(all::OP_DUP)
                                .push_opcode(all::OP_HASH160)
                                .push_slice(&hash160::Hash::hash(public.to_bytes().as_slice())[..])
                                .push_opcode(all::OP_EQUALVERIFY)
                                .push_opcode(all::OP_CHECKSIG)
                                .into_script();

                            let sighash = bip143::SighashComponents::new(&txclone).sighash_all(&txclone.input[ix], &script_code, spend.value);
                            let mut signature = self.context.sign(&sighash[..], pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.witness.push(signature);
                            input.witness.push(public.to_bytes());
                            signed += 1;
                        }
                        AccountAddressType::P2WSH(_) => {}
                    }
                }
            }
        }
        Ok(signed)
    }

    /// sign a transaction with keys in this account works for P2WSH only
    pub fn sign_script<R, W, S> (&self, transaction: &mut Transaction, hash_type: SigHashType, resolver: R, scripter: S, witness: W) -> Result<usize, WalletError>
        where R: Fn(&OutPoint) -> Option<TxOut>, S: Fn(u32, &PublicKey) -> Script, W: Fn(Vec<u8>, &PublicKey) -> Vec<Vec<u8>> {
        let mut signed = 0;
        let txclone = transaction.clone();
        for (ix, input) in transaction.input.iter_mut().enumerate() {
            if let Some(spend) = resolver (&input.previous_output) {
                if let Some((_,pk,public,a)) = self.instantiated.iter().find(|(_,_,_,a)| a.script_pubkey() == spend.script_pubkey) {
                    match self.address_type {
                        AccountAddressType::P2WSH(n) => {
                            if hash_type.as_u32() & SigHashType::All.as_u32() == 0 {
                                return Err(WalletError::Unsupported("can only sig all inputs for now"));
                            }
                            input.script_sig = Script::new();
                            let script_code = scripter(n, public);
                            let sighash = bip143::SighashComponents::new(&txclone).sighash_all(&txclone.input[ix], &script_code, spend.value);
                            let mut signature = self.context.sign(&sighash[..], pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.witness = witness(signature, public);
                            input.witness.push(script_code.to_bytes());
                            signed += 1;
                        },
                        _ => {}
                    }
                }
            }
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::blockdata::transaction::{TxOut, TxIn, OutPoint};
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::opcodes::all;
    use bitcoin::util::address::Payload;
    use bitcoin_hashes::{hash160,sha256d,Hash};
    use context::MasterKeyEntropy;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::io::Cursor;

    #[test]
    fn test_pkh () {

        let ctx = Arc::new(SecpContext::new());
        let (master, _, _) = ctx.new_master_private_key(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        let mut account = Account::new(ctx.clone(), master, AccountAddressType::P2PKH, None, Network::Bitcoin).unwrap();
        let pk = account.receive.new_key(0).unwrap();
        let source = account.receive.get_address(0).unwrap();
        let target = account.receive.get_address(0).unwrap();
        let input_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid: sha256d::Hash::default(), vout: 0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0xffffffff,
            version: 1
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid, vout:0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0xffffffff,
            version: 1
        };

        let mut spent = HashMap::new();
        spent.insert(input_transaction.txid(), input_transaction.clone());

        assert_eq!(account.receive.sign(&mut spending_transaction, SigHashType::All, |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

    #[test]
    fn test_wpkh () {

        let ctx = Arc::new(SecpContext::new());
        let (master, _, _) = ctx.new_master_private_key(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        let mut account = Account::new(ctx.clone(), master, AccountAddressType::P2WPKH, None, Network::Bitcoin).unwrap();
        let pk = account.receive.new_key(0).unwrap();
        let source = account.receive.get_address(0).unwrap();
        let target = account.receive.get_address(0).unwrap();

        let input_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid: sha256d::Hash::default(), vout: 0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0x11000000,
            version: 1
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid, vout:0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0x11000000,
            version: 1
        };

        let mut spent = HashMap::new();
        spent.insert(txid, input_transaction.clone());

        assert_eq!(account.receive.sign(&mut spending_transaction, SigHashType::All, |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

    #[test]
    fn test_shwpkh () {

        let ctx = Arc::new(SecpContext::new());
        let (master, _, _) = ctx.new_master_private_key(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        let mut account = Account::new(ctx.clone(), master, AccountAddressType::P2SHWPKH, None, Network::Bitcoin).unwrap();
        let pk = account.receive.new_key(0).unwrap();
        let source = account.receive.get_address(0).unwrap();
        let target = account.receive.get_address(0).unwrap();

        let input_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid: sha256d::Hash::default(), vout: 0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0x11000000,
            version: 1
        };

        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid, vout:0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0x11000000,
            version: 1
        };

        let mut spent = HashMap::new();
        spent.insert(txid, input_transaction.clone());

        assert_eq!(account.receive.sign(&mut spending_transaction, SigHashType::All, |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

    #[test]
    fn test_wsh () {

        let ctx = Arc::new(SecpContext::new());
        let (master, _, _) = ctx.new_master_private_key(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        let mut account = Account::new(ctx.clone(), master, AccountAddressType::P2WSH(4711), None, Network::Bitcoin).unwrap();

        let scripter = |n: u32, public: &PublicKey| {
            Builder::new()
                .push_opcode(all::OP_DUP)
                .push_opcode(all::OP_HASH160)
                .push_slice(&hash160::Hash::hash(public.to_bytes().as_slice())[..])
                .push_opcode(all::OP_EQUALVERIFY)
                .push_opcode(all::OP_CHECKSIG)
                .into_script()
        };

        let pk = account.receive.new_key_script(0, scripter).unwrap();
        let source = account.receive.get_address(0).unwrap();
        let target = account.receive.get_address(0).unwrap();
        let input_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid: sha256d::Hash::default(), vout: 0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0xffffffff,
            version: 1
        };
        let txid = input_transaction.txid();

        let mut spending_transaction = Transaction {
            input: vec![
                TxIn{
                    previous_output: OutPoint{txid, vout:0},
                    sequence: 0,
                    witness: Vec::new(),
                    script_sig: Script::new()
                }
            ],
            output: vec![
                TxOut{
                    script_pubkey: target.script_pubkey(),
                    value: 5000000000
                }
            ],
            lock_time: 0xffffffff,
            version: 1
        };

        let mut spent = HashMap::new();
        spent.insert(input_transaction.txid(), input_transaction.clone());

        assert_eq!(account.receive.sign_script(
            &mut spending_transaction, SigHashType::All,
            |_| Some(input_transaction.output[0].clone()), scripter,
            |sig, public| {vec!(sig, public.to_bytes())}).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

}