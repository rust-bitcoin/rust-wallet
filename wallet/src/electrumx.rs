//
// Copyright 2018 rust-wallet developers
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
use bitcoin::{
    Transaction, OutPoint,
    consensus::encode::{serialize_hex, deserialize},
};
use hex;

use std::{
    error::Error,
    collections::HashMap,
};

use electrumx_client::{
    electrumx_client::ElectrumxClient,
    interface::Electrumx,
};
use super::walletlibrary::{WalletLibrary, WalletConfig, LockId, WalletLibraryMode};
use super::interface::{WalletLibraryInterface, Wallet};
use super::error::WalletError;
use super::mnemonic::Mnemonic;

pub struct ElectrumxWallet {
    pub wallet_lib: Box<WalletLibraryInterface + Send>,
    electrumx_client: ElectrumxClient<String>,
}

impl Wallet for ElectrumxWallet {
    fn wallet_lib(&self) -> &Box<WalletLibraryInterface + Send> {
        &self.wallet_lib
    }

    fn wallet_lib_mut(&mut self) -> &mut Box<WalletLibraryInterface + Send> {
        &mut self.wallet_lib
    }

    fn reconnect(&mut self) {
        self.electrumx_client = ElectrumxClient::new("127.0.0.1:60401".to_string()).unwrap();
    }

    fn send_coins(
        &mut self,
        addr_str: String,
        amt: u64,
        lock_coins: bool,
        witness_only: bool,
        submit: bool,
    ) -> Result<(Transaction, LockId), Box<Error>> {
        let (tx, lock_id) = self
            .wallet_lib
            .send_coins(addr_str, amt, lock_coins, witness_only)?;
        if submit {
            self.publish_tx(&tx);
        }
        Ok((tx, lock_id))
    }

    fn make_tx(
        &mut self,
        ops: Vec<OutPoint>,
        addr_str: String,
        amt: u64,
        submit: bool,
    ) -> Result<Transaction, Box<Error>> {
        let tx = self.wallet_lib.make_tx(ops, addr_str, amt).unwrap();
        if submit {
            self.publish_tx(&tx);
        }
        Ok(tx)
    }

    fn publish_tx(&mut self, tx: &Transaction) {
        let tx = serialize_hex(tx);
        self.electrumx_client.broadcast_transaction(tx).unwrap();
    }

    // TODO(evg): something better?
    fn sync_with_tip(&mut self) {
        println!("******** SYNC_WITH_TIP_BEGIN ********");
        let mut all_wallet_related_txs = Vec::new();
        let btc_address_list = self.wallet_lib.get_full_address_list();
        for btc_address in btc_address_list {
            let history = self.electrumx_client.get_history(&btc_address).unwrap();
            for resp in history {
                all_wallet_related_txs.push((resp.height, resp.tx_hash))
            }
        }

        // sort txs by height
        // every time sync_with_tip is called we request all wallet related tx and process them
        // in properly order
        // it seems we don't have to clear utxos from memory and database
        // through nature of key-value db, means it's not a problem try to add
        // one utxo several time it will be accept only once
        all_wallet_related_txs.sort();

        let mut to_skip = HashMap::new();
        for wallet_related_tx in all_wallet_related_txs {
            // we don't want to process same tx twice so we skip already processed tx
            if to_skip.contains_key(&wallet_related_tx.1) {
                continue;
            }

            let tx_hash = wallet_related_tx.1;
            let tx_hex = self
                .electrumx_client
                .get_transaction(tx_hash.clone(), false, false)
                .unwrap();
            let tx = hex::decode(tx_hex).unwrap();

            let tx: Transaction = deserialize(&tx).unwrap();
            self.wallet_lib.process_tx(&tx);

            // mark tx as processed
            to_skip.insert(tx_hash, ());
        }
        println!("******** SYNC_WITH_TIP_END ********\n\n\n");
    }
}

impl ElectrumxWallet {
    pub fn new(
        wc: WalletConfig,
        mode: WalletLibraryMode,
    ) -> Result<(ElectrumxWallet, Mnemonic), WalletError> {
        let (wallet_lib, mnemonic) = WalletLibrary::new(wc, mode)?;
        let electrumx_client = ElectrumxClient::new("127.0.0.1:60401".to_string()).unwrap();

        Ok((
            ElectrumxWallet {
                wallet_lib: Box::new(wallet_lib),
                electrumx_client,
            },
            mnemonic,
        ))
    }
}
