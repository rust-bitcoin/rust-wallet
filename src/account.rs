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
//! TREZOR compatible accounts (BIP44)
//!
use bitcoin::util::bip32::{ExtendedPubKey, ExtendedPrivKey,ChildNumber};
use std::sync::Arc;
use keyfactory::KeyFactory;

/// Address type an account is using
pub enum AccountAddressType {
    /// pay to public key hash (aka. legacy)
    P2PKH,
    /// pay to script hash of a witness script (aka. segwit in legacy address format)
    P2SHWH
}

/// a TREZOR compatible account
pub struct Account {
    account_key: ExtendedPrivKey,
    address_type: AccountAddressType,
    key_factory: Arc<KeyFactory>
}

impl Account {
    pub fn new (key_factory: Arc<KeyFactory>, account_key: ExtendedPrivKey, address_type: AccountAddressType) -> Account {
        Account {key_factory, account_key, address_type}
    }
}