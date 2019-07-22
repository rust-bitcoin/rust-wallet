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
use bitcoin::{
    Address,
    util::bip32::{ExtendedPrivKey,ChildNumber},
    network::constants::Network
};
use std::sync::Arc;
use context::SecpContext;
use error::WalletError;

/// Address type an account is using
#[derive(Copy, Clone)]
pub enum AccountAddressType {
    /// pay to public key hash (aka. legacy)
    P2PKH,
    /// pay to script hash of a witness script (aka. segwit in legacy address format)
    P2SHWH
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
    pub fn new (context: Arc<SecpContext>, key: ExtendedPrivKey, address_type: AccountAddressType, birth: u64, network: Network) -> Result<Account, WalletError> {
        let receive = SubAccount{
            context: context.clone(), address_type, birth, next:0,
            key: context.private_child(&key, ChildNumber::Normal{index:0})?,
            network
        };
        let change = SubAccount{
            context: context.clone(), address_type, birth, next:0,
            key: context.private_child(&key, ChildNumber::Normal{index:1})?,
            network
        };
        Ok(Account {context, key: key, address_type, birth, receive, change, network})
    }
}

pub struct SubAccount {
    address_type: AccountAddressType,
    context: Arc<SecpContext>,
    key: ExtendedPrivKey,
    birth: u64,
    network: Network,
    next: u32
}

impl SubAccount {
    pub fn iter_addresses(&self, from: u32) -> AddressIterator {
        AddressIterator::new(self, from)
    }
}

pub struct AddressIterator<'a> {
    account: &'a SubAccount,
    from : u32,
}

impl<'a> AddressIterator<'a> {
    pub fn new (account: &'a SubAccount, from: u32) -> AddressIterator<'a> {
        AddressIterator{from, account}
    }
}

impl<'a> Iterator for AddressIterator<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        let ep = self.account.context.private_child(
            &self.account.key, ChildNumber::Normal {index: self.from}).expect("BIP32 derivation failed");
        let address = match self.account.address_type {
            AccountAddressType::P2PKH => Address::p2pkh(&self.account.context.public_from_private(&ep.private_key), self.account.network),
            AccountAddressType::P2SHWH => Address::p2shwpkh(&self.account.context.public_from_private(&ep.private_key), self.account.network)
        };
        self.from += 1;
        Some(address)
    }
}