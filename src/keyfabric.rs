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
use crypto::aes;
use crypto::blockmodes;
use crypto::buffer;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use rand::{OsRng, RngCore};
use mnemonic;

/// a fabric of keys
pub struct KeyFabric {
    secp: Secp256k1
}

impl KeyFabric {
    /// new key fabric
    pub fn new() -> KeyFabric {
        KeyFabric {
            secp: Secp256k1::new()
        }
    }

    ///
    /// Generate new random master private key as follows:
    /// 1. get random 64 bytes from OS and consider it as encrypted data for persistent storage.
    /// 2. decrypt encrypted data using Sha256 hashed passphrase as key with AES ECB NoPadding
    /// 3. generate human readable mnemonic out of decrypted data
    /// 4. generate seed from mnemonic with PBKDF2(Hmac(SHA512), 2048 iterations, salt)
    /// 5. create BIP32 extended private from seed
    ///
    pub fn new_master_private_key (&self, passphrase: &str, salt: &str, network: Network) -> Result<(ExtendedPrivKey, String, Vec<u8>), WalletError> {
        let mut encrypted_seed = [0u8; 64];
        if let Ok(mut rnd) = OsRng::new() {
            rnd.fill_bytes(&mut encrypted_seed);
            let data = KeyFabric::decrypt_seed(&encrypted_seed, passphrase)?;
            let mnemonic = mnemonic::mnemonic(&data)?;
            let seed = mnemonic::seed(mnemonic.as_str(), salt);
            let key = self.master_private_key(network, seed.as_slice())?;
            Ok((key, mnemonic, encrypted_seed.to_vec()))
        }
        else {
            Err(WalletError::Generic("can not obtain random source"))
        }
    }

    /// decrypt an encrypted seed (AES)
    pub fn decrypt_seed (encrypted_seed: &[u8], passphrase: &str) -> Result<Vec<u8>, WalletError> {
        let mut key = [0u8; 32];
        let mut seed = vec!(0u8; encrypted_seed.len());
        let mut sha2 = Sha256::new();
        sha2.input(passphrase.as_bytes());
        sha2.result(&mut key);
        let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize256, &key, blockmodes::NoPadding{});
        decryptor.decrypt(&mut buffer::RefReadBuffer::new(encrypted_seed),
        &mut buffer::RefWriteBuffer::new(seed.as_mut_slice()), true)?;
        Ok(seed)
    }

    /// create a master private key from a seed
    pub fn master_private_key(&self, network: Network, seed: &[u8]) -> Result<ExtendedPrivKey, WalletError> {
        Ok(ExtendedPrivKey::new_master (&self.secp, network, seed)?)
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

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::Read;
    use bitcoin::network::constants::Network;
    use bitcoin::util::bip32::ChildNumber;


    extern crate rustc_serialize;
    extern crate hex;
    use self::rustc_serialize::json::Json;
    use self::hex::decode;

    #[test]
    fn bip32_tests () {
        let key_fabric = super::KeyFabric::new();

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/BIP32.json");
        let mut file = File::open(d).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json = Json::from_str(&data).unwrap();
        let tests = json.as_array().unwrap();
        for test in tests {
            let seed = decode(test["seed"].as_string().unwrap()).unwrap();
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