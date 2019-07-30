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

use bitcoin::{BitcoinHash, BlockHeader, Script};
use bitcoin_hashes::{Hash, HashEngine, sha256d};
use bitcoin::{OutPoint, TxOut, Transaction};
use bitcoin::Block;
use std::collections::HashMap;
use crate::masteraccount::MasterAccount;
use crate::error::WalletError;
use crate::proved::ProvedTransaction;


/// A wallet
pub struct Wallet {
    pub master: MasterAccount,
    owned: HashMap<OutPoint, TxOut>,
    proofs: HashMap<sha256d::Hash, ProvedTransaction>,
    headers: Vec<BlockHeader>,
    processed_height: u32
}

impl Wallet {
    /// get the tip hash of the header chain
    pub fn get_tip (&self) -> Option<&BlockHeader> {
        self.headers.last()
    }

    /// get the chain height
    pub fn get_height(&self) -> u32 {
        self.headers.len() as u32
    }

    /// add a header to the tip of the chain
    /// the caller should do SPV check and evtl. unwind
    /// before adding this header after a reorg.
    pub fn add_header(&mut self, header: BlockHeader) -> Result<(), WalletError> {
        if self.headers.len() > 0 {
            if self.get_tip().unwrap().bitcoin_hash() == header.prev_blockhash {
                self.headers.push(header);
            }
            else {
                return Err(WalletError::Unsupported("only add header connected to tip"));
            }
        }
        else {
            // add genesis
            self.headers.push(header);
        }
        Ok(())
    }

    /// unwind the tip
    pub fn unwind_tip(&mut self) -> Result<(), WalletError> {
        let len = self.headers.len();
        if len > 0 {
            self.headers.remove(len-1);
            if self.processed_height as usize == len-1 {
                // this means we might have lost control of coins at least temporarily
                let lost_coins = self.proofs.values()
                    .filter_map(|t| if t.get_block_height() as usize == len - 1 {
                        Some(t.get_transaction().txid())
                    } else { None })
                    .flat_map(|txid| self.owned.keys().filter(move |point| point.txid == txid)).cloned().collect::<Vec<OutPoint>>();

                for point in lost_coins {
                    self.proofs.remove(&point.txid);
                    self.owned.remove(&point);
                }
                self.processed_height -= 1;
            }
            return Ok(())
        }
        Err(WalletError::Unsupported("unwind on empty chain"))
    }
    /// skip blocks before birth of our keys
    pub fn skip_blocks (&mut self, birth: u64) {
        if let Some(later) = self.headers.iter().position(|h| h.time as u64 > birth) {
            self.processed_height = (later - 1) as u32;
        }
        else {
            self.processed_height = (self.headers.len()-1) as u32;
        }
    }

    /// process a block
    /// have to process all blocks as we have no BIP158 filters yet
    pub fn process(&mut self, height: u32, block: &Block) -> Result<(), WalletError> {
        if height < self.processed_height {
            return Err(WalletError::Unsupported("can only process blocks in consecutive order"));
        }
        if block.header.bitcoin_hash() != self.headers[height as usize].bitcoin_hash() {
            return Err(WalletError::Unsupported("not the block expected"));
        }

        let mut scripts : HashMap<Script, (u32, u32, u32)> = self.master.get_scripts()
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
                    self.owned.insert(OutPoint{txid: tx.txid(), vout: vout as u32}, output.clone());
                    self.proofs.entry(tx.txid()).or_insert(ProvedTransaction::new(height, block, txnr));
                }
                for (a, sub, kix, s) in lookahead {
                    scripts.insert(s, (a, sub, kix));
                }
            }
        }
        self.processed_height = height;
        Ok(())
    }

    pub fn get_coins<V> (&self,  minimum: u64, scripts: impl Iterator<Item=Script>, validator: V) -> Vec<(OutPoint, TxOut)>
        where V: Fn(u32, &Script) -> bool {
        let mut sum = 0u64;
        scripts.flat_map(|s| self.owned.iter()
            .filter_map(|(p, o)| if o.script_pubkey == s && validator(self.proofs.get(&p.txid).unwrap().get_block_height(), &o.script_pubkey) {
                Some((p.clone(), o.clone()))
            }else{None}).collect::<Vec<(OutPoint, TxOut)>>())
            .take_while(move |(p, o)| {sum += o.value; sum < minimum}).collect::<Vec<(OutPoint, TxOut)>>()
    }

    pub fn get_confirmed_height(&self, txid: &sha256d::Hash) -> Result<u32, WalletError> {
        if let Some(proof) = self.proofs.get(txid) {
            return Ok(proof.get_block_height());
        }
        return Err(WalletError::Unsupported("not a confirmed transaction"));
    }
}
