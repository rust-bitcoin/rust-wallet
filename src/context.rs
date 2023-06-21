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
//! # Key derivation
//!
use bitcoin::secp256k1::{ecdsa::Signature, All, Message, Scalar, Secp256k1};
use bitcoin::{
    network::constants::Network,
    util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey},
    PrivateKey, PublicKey,
};

use account::Seed;
use error::Error;
use std::convert::TryInto;

pub struct SecpContext {
    secp: Secp256k1<All>,
}

impl SecpContext {
    pub fn new() -> SecpContext {
        SecpContext {
            secp: Secp256k1::new(),
        }
    }

    /// create a master private key from seed
    pub fn master_private_key(
        &self,
        network: Network,
        seed: &Seed,
    ) -> Result<ExtendedPrivKey, Error> {
        Ok(ExtendedPrivKey::new_master(network, &seed.0)?)
    }

    /// get extended public key for a known private key
    pub fn extended_public_from_private(
        &self,
        extended_private_key: &ExtendedPrivKey,
    ) -> ExtendedPubKey {
        ExtendedPubKey::from_priv(&self.secp, extended_private_key)
    }

    pub fn private_child(
        &self,
        extended_private_key: &ExtendedPrivKey,
        child: ChildNumber,
    ) -> Result<ExtendedPrivKey, Error> {
        Ok(extended_private_key.ckd_priv(&self.secp, child)?)
    }

    pub fn public_child(
        &self,
        extended_public_key: &ExtendedPubKey,
        child: ChildNumber,
    ) -> Result<ExtendedPubKey, Error> {
        Ok(extended_public_key.ckd_pub(&self.secp, child)?)
    }

    pub fn public_from_private(&self, private: &PrivateKey) -> PublicKey {
        PublicKey::from_private_key(&self.secp, private)
    }

    pub fn sign(&self, digest: &[u8], key: &PrivateKey) -> Result<Signature, Error> {
        Ok(self
            .secp
            .sign_ecdsa(&Message::from_slice(digest)?, &key.inner))
    }

    pub fn tweak_add(&self, key: &mut PrivateKey, tweak: &[u8]) -> Result<(), Error> {
        // Convert tweak here since Scalar omits Debug derivation so we can't add to KeyDerivation
        let tweak =
            Scalar::from_be_bytes(tweak.try_into().map_err(|e| Error::TryFromSliceError(e))?)
                .map_err(|e| Error::OutOfRangeError(e))?;
        key.inner.add_tweak(&tweak)?;
        Ok(())
    }

    pub fn tweak_exp_add(&self, key: &mut PublicKey, tweak: &[u8]) -> Result<(), Error> {
        // Convert tweak here since Scalar omits Debug derivation so we can't add to KeyDerivation
        let tweak =
            Scalar::from_be_bytes(tweak.try_into().map_err(|e| Error::TryFromSliceError(e))?)
                .map_err(|e| Error::OutOfRangeError(e))?;
        key.inner.add_exp_tweak(&self.secp, &tweak)?;
        Ok(())
    }
}
