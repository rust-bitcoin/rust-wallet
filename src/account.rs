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

use std::sync::Arc;
use std::time::SystemTime;

use bitcoin::{
    Address, blockdata::{
        opcodes::all,
        transaction::{SigHashType, TxOut},
    }, blockdata::script::Builder, network::constants::Network, OutPoint, PrivateKey,
    PublicKey,
    Script,
    Transaction,
    util::bip143,
    util::bip32::{ChildNumber, ExtendedPrivKey},
};
use bitcoin_hashes::{Hash, hash160};

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
    /// Only supports scripts that can be spent with following witness:
    /// <signature> <scriptCode>
    P2WSH(u32),
}

/// a TREZOR compatible account
pub struct Account {
    birth: u64,
    // seconds in unix epoch
    sub: Vec<SubAccount>
}

impl Account {
    /// create a new account
    pub fn new(context: Arc<SecpContext>, key: ExtendedPrivKey, address_type: AccountAddressType, birth: Option<u64>, used: Vec<u32>, look_ahead: u32, network: Network) -> Result<Account, WalletError> {
        let birth = birth.unwrap_or(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

        let mut sub = Vec::new();
        for (i, u) in used.iter().enumerate() {
            let mut s = SubAccount {
                context: context.clone(),
                address_type,
                key: context.private_child(&key, ChildNumber::Normal { index: i as u32 })?,
                instantiated: Vec::new(),
                next: 0,
                look_ahead,
                network,
            };
            s.look_ahead(0)?;
            for _ in 0..*u {
                s.next_key()?;
            }
            sub.push(s);
        }

        Ok(Account { birth, sub })
    }

    pub fn birth(&self) -> u64 {
        self.birth
    }

    // get all pubkey scripts of this account
    pub fn get_scripts<'a>(&'a self) -> impl Iterator<Item=(u32, u32, Script)> + 'a {
        self.sub.iter().enumerate().flat_map(|(i, s)| s.get_scripts().map(move |(kix, script)| (i as u32, kix, script)))
    }

    pub fn iter(&self) -> impl Iterator<Item=&SubAccount> {
        self.sub.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item=&mut SubAccount> {
        self.sub.iter_mut()
    }

    pub fn get(&self, s: u32) -> Option<&SubAccount> {
        self.sub.get(s as usize)
    }

    pub fn get_mut (&mut self, s: u32) -> Option<&mut SubAccount> {
        self.sub.get_mut(s as usize)
    }
}

/// instantiated key of an account
#[derive(Clone)]
pub struct Instantiated {
    pub pk: PrivateKey,
    pub public: PublicKey,
    pub script_code: Script,
    pub address: Address,
    pub script_pubkey: Script,
}

impl Instantiated {
    pub fn new_from_extended_key(address_type: AccountAddressType, network: Network, kix: u32, ek: &ExtendedPrivKey, context: Arc<SecpContext>) -> Result<Instantiated, WalletError> {
        return Self::new(address_type, network, context.private_child(&ek, ChildNumber::Normal { index: kix })?.private_key, None, None, context);
    }

    pub fn new(address_type: AccountAddressType, network: Network, mut pk: PrivateKey, tweak: Option<&[u8]>, script_code: Option<Script>, context: Arc<SecpContext>) -> Result<Instantiated, WalletError> {
        if let Some(tweak) = tweak {
            pk = pk.clone();
            pk.key.add_assign(tweak)?;
        }
        let public = context.public_from_private(&pk);
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
        Ok(Instantiated {
            pk,
            public,
            script_code,
            address,
            script_pubkey,
        })
    }
}


pub struct SubAccount {
    address_type: AccountAddressType,
    context: Arc<SecpContext>,
    key: ExtendedPrivKey,
    instantiated: Vec<Instantiated>,
    next: u32,
    look_ahead: u32,
    network: Network,
}

impl SubAccount {
    /// look ahead one more key
    pub fn look_ahead(&mut self, seen: u32) -> Result<Vec<(u32, Script)>, WalletError> {
        use std::cmp::max;

        let have = self.instantiated.len() as u32;
        let need = max(seen + self.look_ahead, have) - have;
        let mut new = Vec::new();
        for i in 0..need {
            new.push((have + i, self.instantiate_next()?.script_pubkey.clone()));
        }
        Ok(new)
    }

    fn instantiate_next(&mut self) -> Result<&Instantiated, WalletError> {
        // keep looking ahead
        let instantiated = Instantiated::new_from_extended_key(self.address_type, self.network,
                                                               self.instantiated.len() as u32, &self.key,
                                                               self.context.clone())?;
        let len = self.instantiated.len();
        self.instantiated.push(instantiated);
        Ok(&self.instantiated[len])
    }

    /// create a new key
    pub fn next_key(&mut self) -> Result<(u32, &Instantiated), WalletError> {
        // keep looking ahead
        self.instantiate_next()?;

        // get next key
        let kix = self.next;
        let ref instantiated = self.instantiated[kix as usize];
        self.next += 1;


        Ok((kix, instantiated))
    }

    /// get last instantiated key
    pub fn last_key (&self) -> (u32, &Instantiated) {
        let kix = self.next;
        let ref instantiated = self.instantiated[kix as usize];
        (kix, instantiated)
    }

    pub fn add_script_key(&mut self, pk: PrivateKey, script_code: Script) -> Result<u32, WalletError> {
        match self.address_type {
            AccountAddressType::P2WSH(_) => {}
            _ => return Err(WalletError::Unsupported("add_script_key can only be used for P2WSH accounts"))
        }
        let instantiated = Instantiated::new(self.address_type, self.network, pk,
                                             None, Some(script_code),
                                             self.context.clone())?;
        self.instantiated.push(instantiated);
        Ok((self.instantiated.len() - 1) as u32)
    }

    pub fn used(&self) -> usize {
        self.next as usize
    }

    // get all pubkey scripts of this account
    pub fn get_scripts<'a>(&'a self) -> impl Iterator<Item=(u32, Script)> + 'a {
        self.instantiated.iter().enumerate().map(|(kix, i)| (kix as u32, i.script_pubkey.clone()))
    }

    /// get a previously created private key for an index with optional additive tweak
    pub fn get_key(&self, ix: u32) -> Option<PrivateKey> {
        if let Some(i) = self.instantiated.get(ix as usize) {
            return Some(i.pk.clone());
        }
        None
    }

    /// get the address for an index, key for this index must have been created earlier
    pub fn get_address(&self, ix: u32) -> Option<Address> {
        if let Some(i) = self.instantiated.get(ix as usize) {
            return Some(i.address.clone());
        }
        None
    }

    /// sign a transaction with keys in this account works for types except P2WSH
    pub fn sign<R>(&self, transaction: &mut Transaction, hash_type: SigHashType, resolver: R) -> Result<usize, WalletError>
        where R: Fn(&OutPoint) -> Option<TxOut> {
        let mut signed = 0;
        let txclone = transaction.clone();
        let mut bip143hasher: Option<bip143::SighashComponents> = None;
        for (ix, input) in transaction.input.iter_mut().enumerate() {
            if let Some(spend) = resolver(&input.previous_output) {
                if let Some(instantiated) =
                self.instantiated.iter().find(|i| i.script_pubkey == spend.script_pubkey) {
                    match self.address_type {
                        AccountAddressType::P2PKH => {
                            let sighash = txclone.signature_hash(ix, &instantiated.address.script_pubkey(), hash_type.as_u32());
                            let mut signature = self.context.sign(&sighash[..], &instantiated.pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.script_sig = Builder::new()
                                .push_slice(signature.as_slice())
                                .push_slice(instantiated.public.to_bytes().as_slice()).into_script();
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
                            let mut signature = self.context.sign(&sighash[..], &instantiated.pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.witness.push(signature);
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
                            let mut signature = self.context.sign(&sighash[..], &instantiated.pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.witness.push(signature);
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
                            let mut signature = self.context.sign(&sighash[..], &instantiated.pk)?.serialize_der();
                            signature.push(hash_type.as_u32() as u8);
                            input.witness.push(signature);
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use bitcoin::blockdata::opcodes::all;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
    use bitcoin_hashes::sha256d;

    use context::MasterKeyEntropy;

    use super::*;
    use masteraccount::MasterAccount;

    #[test]
    fn test_pkh() {
        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        master.add_account(AccountAddressType::P2PKH, 1, 10).unwrap();
        let account = master.get_mut(0).unwrap().get_mut(0).unwrap();
        let (_, i) = account.next_key().unwrap();
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

        assert_eq!(account.sign(&mut spending_transaction, SigHashType::All, |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

    #[test]
    fn test_wpkh() {
        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        master.add_account(AccountAddressType::P2WPKH, 1, 10).unwrap();
        let account = master.get_mut(0).unwrap().get_mut(0).unwrap();
        let (_, i) = account.next_key().unwrap();
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

        assert_eq!(account.sign(&mut spending_transaction, SigHashType::All, |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

    #[test]
    fn test_shwpkh() {
        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        master.add_account(AccountAddressType::P2SHWPKH, 1, 10).unwrap();
        let account = master.get_mut(0).unwrap().get_mut(0).unwrap();
        let (_, i) = account.next_key().unwrap();
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

        assert_eq!(account.sign(&mut spending_transaction, SigHashType::All, |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }

    #[test]
    fn test_wsh() {
        let ctx = Arc::new(SecpContext::new());

        let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, "", "TREZOR").unwrap();
        master.add_account(AccountAddressType::P2SHWPKH, 1, 10).unwrap();
        master.add_account(AccountAddressType::P2WSH(4711), 1, 0).unwrap();

        let pk;
        {
            let base_account = master.get_mut(0).unwrap().get_mut(0).unwrap();
            let (_, i) = base_account.next_key().unwrap();
            pk = i.pk;
        }
        let account = master.get_mut(1).unwrap().get_mut(0).unwrap();


        // optional: add some tweak
        let pk = ctx.tweak_add(&pk, &[0x01; 32]).unwrap();

        let scrip_code = Builder::new()
            .push_slice(ctx.public_from_private(&pk).to_bytes().as_slice())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        let ix = account.add_script_key(pk, scrip_code).unwrap();
        let source = account.get_address(ix).unwrap();
        let target = account.get_address(ix).unwrap();
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

        assert_eq!(account.sign(
            &mut spending_transaction, SigHashType::All,
            |_| Some(input_transaction.output[0].clone())).unwrap(), 1);

        spending_transaction.verify(&spent).unwrap();
    }
}