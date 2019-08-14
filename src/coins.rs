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

use bitcoin_hashes::sha256d;
use bitcoin::{OutPoint, TxOut};
use bitcoin::Block;
use std::collections::HashMap;
use account::MasterAccount;
use proved::ProvedTransaction;

/// Manage owned coins
pub struct Coins {
    owned: HashMap<OutPoint, (TxOut, u32, u32, u32, Option<Vec<u8>>)>,
    proofs: HashMap<sha256d::Hash, ProvedTransaction>,
}

impl Coins {
    pub fn new () -> Coins {
        Coins { owned: HashMap::new(), proofs: HashMap::new() }
    }

    pub fn prove (&self, txid: &sha256d::Hash) -> Option<&ProvedTransaction> {
        self.proofs.get(txid)
    }

    /// unwind the tip of the trunk
    pub fn unwind_tip(&mut self, block_hash: &sha256d::Hash) {
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
    }

    /// process a block to find own coins
    /// processing should be in ascending height order, it is fine to skip blocks  if you know
    /// there is nothing in them you would care (this will be easy to tell with committed BIP158
    /// filters, but we are not yet there)
    pub fn process(&mut self, master_account: &mut MasterAccount, block: &Block) {
        let mut scripts: HashMap<_,_> = master_account.get_scripts()
            .map(|(a, sub, k, s, t)| (s, (a, sub, k, t))).collect();

        for (txnr, tx) in block.txdata.iter().enumerate() {
            for input in tx.input.iter().skip(1) {
                self.owned.remove(&input.previous_output);
                if self.owned.iter().any(|(point,_)| point.txid == input.previous_output.txid) == false {
                    self.proofs.remove(&input.previous_output.txid);
                }
            }
            for (vout, output) in tx.output.iter().enumerate() {
                let mut lookahead = Vec::new();
                if let Some((a, sub, seen, t)) = scripts.get(&output.script_pubkey) {
                    lookahead =
                        master_account.get_mut((*a, *sub)).unwrap().do_look_ahead(*seen).unwrap()
                            .iter().map(move |(kix, s)| (*a, *sub, *kix, s.clone(), t.clone())).collect();
                    self.owned.insert(OutPoint { txid: tx.txid(), vout: vout as u32 },
                                      (output.clone(), *a, *sub, *seen, t.clone()));
                    self.proofs.entry(tx.txid()).or_insert(ProvedTransaction::new(block, txnr));
                }
                for (a, sub, kix, s, t) in lookahead {
                    scripts.insert(s, (a, sub, kix, t));
                }
            }
        }
    }

    /// get random owned coins of sufficient amount that pass a filter
    /// The filter is called with parameters:
    /// block_hash the coin was confirmed in
    /// transaction id with coin output
    /// coin output within the transaction
    /// account number
    /// sub account number
    /// key index
    /// optional tweak
    pub fn get_coins<V> (&self,  minimum: u64, filter: V) -> Vec<(OutPoint, TxOut, u32, u32, u32, Option<Vec<u8>>)>
        where V: Fn(&sha256d::Hash, &OutPoint, &TxOut, &u32, &u32, &u32, &Option<Vec<u8>>) -> bool {
        let mut sum = 0u64;

        self.owned.iter()
            .filter_map(|(p, (o, a, sub, k, t))|
                if filter(self.proofs.get(&p.txid).unwrap().get_block_hash(), &p, &o, a, sub, k, t) {
                    Some((p.clone(), o.clone(), *a, *sub, *k, t.clone()))
                }else{
                    None
                }
            ).take_while(move |(_, o, _, _, _, _)| {sum += o.value; sum < minimum}).collect()
    }
}
