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
//! # Key derivation
//!
//! TREZOR compatible key derivation
//!
use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{ExtendedPubKey, ExtendedPrivKey,ChildNumber};
use secp256k1::Secp256k1;
use error::WalletError;
use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha2::Sha512;
use rand::{OsRng, RngCore};
use mnemonic::Mnemonic;

/// a fabric of keys
pub struct KeyFactory {
    secp: Secp256k1,
    rng: OsRng
}

impl KeyFactory {
    /// new key fabric
    pub fn new() -> KeyFactory {
        KeyFactory {
            secp: Secp256k1::new(),
            rng: OsRng::new().expect("Can not obtain random source.")
        }
    }

    /// create a new random master private key
    pub fn new_master_private_key (&mut self, entropy: MasterKeyEntropy, network: Network, passphrase: &str, salt: &str) -> Result<(ExtendedPrivKey, Mnemonic, Vec<u8>), WalletError> {
        let mut encrypted = vec!(0u8; entropy as usize);
        self.rng.fill_bytes(encrypted.as_mut_slice());
        let mnemonic = Mnemonic::new(&encrypted, passphrase)?;
        let seed = Seed::new(&mnemonic, salt);
        let key = self.master_private_key(network, &seed)?;
        Ok((key, mnemonic, encrypted))
    }

    /// create a master private key from seed
    pub fn master_private_key(&self, network: Network, seed: &Seed) -> Result<ExtendedPrivKey, WalletError> {
        Ok(ExtendedPrivKey::new_master (&self.secp, network, &seed.0)?)
    }

    /// get extended public key for a known private key
    pub fn extended_public_from_private(&self, extended_private_key: &ExtendedPrivKey) -> ExtendedPubKey {
        ExtendedPubKey::from_private(&self.secp, extended_private_key)
    }

    pub fn private_child (&self, extended_private_key: &ExtendedPrivKey, child: ChildNumber) -> Result<ExtendedPrivKey, WalletError> {
        Ok(extended_private_key.ckd_priv(&self.secp, child)?)
    }

    pub fn public_child (&self, extended_public_key: &ExtendedPubKey, child: ChildNumber) -> Result<ExtendedPubKey, WalletError> {
        Ok(extended_public_key.ckd_pub(&self.secp, child)?)
    }
}

#[derive(Copy, Clone)]
pub enum MasterKeyEntropy {
    Low = 16,
    Recommended = 32,
    Paranoid = 64
}

pub struct Seed(Vec<u8>);

impl Seed {
    // return a copy of the seed data
    pub fn data (&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Seed {
    /// create a seed from mnemonic (optionally with salt)
    pub fn new(mnemonic: &Mnemonic, salt: &str) -> Seed {
        let mut mac = Hmac::new(Sha512::new(), mnemonic.to_string().as_bytes());
        let mut output = [0u8; 64];
        let msalt = "mnemonic".to_owned() + salt;
        pbkdf2(&mut mac, msalt.as_bytes(), 2048, &mut output);
        Seed(output.to_vec())
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::Read;
    use bitcoin::network::constants::Network;
    use bitcoin::util::bip32::ChildNumber;
    use keyfactory::Seed;

    extern crate rustc_serialize;
    extern crate hex;
    use self::rustc_serialize::json::Json;
    use self::hex::decode;

    #[test]
    fn bip32_tests () {
        let key_fabric = super::KeyFactory::new();

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/BIP32.json");
        let mut file = File::open(d).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json = Json::from_str(&data).unwrap();
        let tests = json.as_array().unwrap();
        for test in tests {
            let seed = Seed(decode(test["seed"].as_string().unwrap()).unwrap());
            let master_private = key_fabric.master_private_key(Network::Bitcoin, &seed).unwrap();
            assert_eq!(test["private"].as_string().unwrap(), master_private.to_string());
            assert_eq!(test["public"].as_string().unwrap(), key_fabric.extended_public_from_private(&master_private).to_string());
            for d in test["derived"].as_array().unwrap() {
                let mut key = master_private.clone();
                for l in d ["locator"].as_array().unwrap() {
                    let sequence = l ["sequence"].as_u64().unwrap();
                    let private = l ["private"].as_boolean().unwrap();
                    let child = if private {
                        ChildNumber::Hardened(sequence as u32)
                    } else {
                        ChildNumber::Normal(sequence as u32)
                    };
                    key = key_fabric.private_child(&key.clone(), child).unwrap();
                }
                assert_eq!(d ["private"].as_string().unwrap(), key.to_string());
                assert_eq!(d ["public"].as_string().unwrap(), key_fabric.extended_public_from_private(&key).to_string());
            }
        }
    }
}