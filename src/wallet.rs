//
// Copyright 2019 Tamas Blummer
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
//! # Wallet
//!
//!

use bitcoin::{BitcoinHash, Script};
use bitcoin_hashes::sha256d;
use bitcoin::{OutPoint, TxOut};
use bitcoin::Block;
use std::collections::HashMap;
use masteraccount::MasterAccount;
use error::WalletError;
use proved::ProvedTransaction;
use trunk::Trunk;

/// A wallet
pub struct Wallet {
    pub master: MasterAccount,
    owned: HashMap<OutPoint, TxOut>,
    proofs: HashMap<sha256d::Hash, ProvedTransaction>,
    trunk: Box<dyn Trunk>,
    processed_height: u32
}

impl Wallet {
    /// unwind the tip
    pub fn unwind_tip(&mut self, block_hash: &sha256d::Hash) -> Result<(), WalletError> {
        if let Some(tip) = self.trunk.get_tip() {
            if self.processed_height == self.trunk.len() + 1 {
                // this means we might have lost control of coins at least temporarily
                let lost_coins = self.proofs.values()
                    .filter_map(|t| if *t.get_block_hash() == *block_hash {
                        Some(t.get_transaction().txid())
                    } else { None })
                    .flat_map(|txid| self.owned.keys().filter(move |point| point.txid == txid)).cloned().collect::<Vec<OutPoint>>();

                for point in lost_coins {
                    self.proofs.remove(&point.txid);
                    self.owned.remove(&point);
                }
                self.processed_height -= 1;
                return Ok(())
            }
        }
        Err(WalletError::Unsupported("unwind not on tip"))
    }

    /// process a block
    /// have to process all blocks as we have no BIP158 filters yet
    pub fn process(&mut self, height: u32, block: &Block) -> Result<(), WalletError> {
        if height < self.processed_height {
            return Err(WalletError::Unsupported("can only process blocks in consecutive order"));
        }
        if let Some(h) = self.trunk.get_height(&block.header.bitcoin_hash()) {
            if h != height {
                return Err(WalletError::Unsupported("not the block expected at this height"));
            }
            let mut scripts: HashMap<Script, (u32, u32, u32)> = self.master.get_scripts()
                .map(|(a, sub, k, s)| (s, (a, sub, k))).collect();

            let mut spends = Vec::new();

            for (txnr, tx) in block.txdata.iter().enumerate() {
                for input in tx.input.iter().skip(1) {
                    if let Some(spend) = self.owned.remove(&input.previous_output) {
                        spends.push((input.previous_output.clone(), spend.clone()));
                    }
                }
                for (vout, output) in tx.output.iter().enumerate() {
                    let mut lookahead = Vec::new();
                    if let Some((a, sub, seen)) = scripts.get(&output.script_pubkey) {
                        lookahead =
                            self.master.get_mut(*a).unwrap().get_mut(*sub).unwrap().look_ahead(*seen).unwrap()
                                .iter().map(move |(kix, s)| (*a, *sub, *kix, s.clone())).collect();
                        self.owned.insert(OutPoint { txid: tx.txid(), vout: vout as u32 }, output.clone());
                        self.proofs.entry(tx.txid()).or_insert(ProvedTransaction::new(block, txnr));
                    }
                    for (a, sub, kix, s) in lookahead {
                        scripts.insert(s, (a, sub, kix));
                    }
                }
            }
            self.processed_height = height;
            return Ok(());
        }
        Err(WalletError::Unsupported("block is not on trunk"))
    }

    pub fn get_coins<V> (&self,  minimum: u64, scripts: impl Iterator<Item=Script>, validator: V) -> Vec<(OutPoint, TxOut)>
        where V: Fn(&sha256d::Hash, &Script) -> bool {
        let mut sum = 0u64;
        scripts.flat_map(|s| self.owned.iter()
            .filter_map(|(p, o)| if o.script_pubkey == s && validator(self.proofs.get(&p.txid).unwrap().get_block_hash(), &o.script_pubkey) {
                Some((p.clone(), o.clone()))
            }else{None}).collect::<Vec<(OutPoint, TxOut)>>())
            .take_while(move |(_, o)| {sum += o.value; sum < minimum}).collect::<Vec<(OutPoint, TxOut)>>()
    }
}
