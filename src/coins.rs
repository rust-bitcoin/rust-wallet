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
//! # Owned coins
//!
//!

use std::collections::HashMap;

use bitcoin::Block;
use bitcoin::{OutPoint, Script, Transaction, TxOut};
use rand::thread_rng;

use account::{KeyDerivation, MasterAccount};
use proved::ProvedTransaction;

#[derive(Clone, Debug, Eq, PartialEq)]
/// a coin is defined by the spendable output
/// the key derivation that allows to spend it
pub struct Coin {
    pub output: TxOut,
    pub derivation: KeyDerivation,
}

/// Manage coins
#[derive(Eq, PartialEq)]
pub struct Coins {
    /// unconfirmed coins
    unconfirmed: HashMap<OutPoint, Coin>,
    /// confirmed coins (these have SPV proofs)
    confirmed: HashMap<OutPoint, Coin>,
    /// SPV proofs of transactions confirming coins
    proofs: HashMap<bitcoin::Txid, ProvedTransaction>,
}

impl Coins {
    pub fn new() -> Coins {
        Coins {
            confirmed: HashMap::new(),
            proofs: HashMap::new(),
            unconfirmed: HashMap::new(),
        }
    }

    /// this should only be used to restore previously computed state
    pub fn add_confirmed(&mut self, point: OutPoint, coin: Coin, proof: ProvedTransaction) {
        self.confirmed.insert(point, coin);
        self.proofs.insert(proof.get_transaction().txid(), proof);
    }

    pub fn remove_confirmed(&mut self, point: &OutPoint) -> bool {
        let modified = self.confirmed.remove(point).is_some();
        if modified && self.confirmed.iter().any(|(p, _)| p.txid == point.txid) == false {
            self.proofs.remove(&point.txid);
        }
        modified
    }

    /// process an unconfirmed transaction. Useful eg. to process own spends.
    pub fn process_unconfirmed_transaction(
        &mut self,
        master_account: &mut MasterAccount,
        transaction: &Transaction,
    ) -> bool {
        let mut scripts: HashMap<Script, KeyDerivation> = master_account.get_scripts().collect();
        let mut modified = false;
        for input in transaction.input.iter() {
            modified |= self.remove_confirmed(&input.previous_output);
        }
        for (vout, output) in transaction.output.iter().enumerate() {
            let mut lookahead = Vec::new();
            if let Some(d) = scripts.get(&output.script_pubkey) {
                lookahead = master_account
                    .get_mut((d.account, d.sub))
                    .unwrap()
                    .do_look_ahead(Some(d.kix))
                    .unwrap()
                    .iter()
                    .map(move |(kix, s)| {
                        (
                            s.clone(),
                            KeyDerivation {
                                kix: *kix,
                                account: d.account,
                                sub: d.sub,
                                tweak: d.tweak.clone(),
                                csv: d.csv.clone(),
                            },
                        )
                    })
                    .collect();
                self.unconfirmed.insert(
                    OutPoint {
                        txid: transaction.txid(),
                        vout: vout as u32,
                    },
                    Coin {
                        output: output.clone(),
                        derivation: d.clone(),
                    },
                );
                modified = true;
            }
            for (s, d) in lookahead {
                scripts.insert(s.clone(), d);
            }
        }
        modified
    }

    pub fn confirmed(&self) -> &HashMap<OutPoint, Coin> {
        &self.confirmed
    }

    pub fn unconfirmed(&self) -> &HashMap<OutPoint, Coin> {
        &self.unconfirmed
    }

    pub fn proofs(&self) -> &HashMap<bitcoin::Txid, ProvedTransaction> {
        &self.proofs
    }

    pub fn available_balance<H>(&self, height: u32, block_height: H) -> u64
    where
        H: Fn(&bitcoin::BlockHash) -> Option<u32>,
    {
        self.available_coins(height, block_height)
            .iter()
            .map(|(_, c, _)| c.output.value)
            .sum::<u64>()
    }

    pub fn available_coins<H>(&self, height: u32, block_height: H) -> Vec<(OutPoint, Coin, u32)>
    where
        H: Fn(&bitcoin::BlockHash) -> Option<u32>,
    {
        self.confirmed
            .iter()
            .filter_map(|(p, c)| {
                let confirmed = self
                    .proofs
                    .get(&p.txid)
                    .expect("confirmed coin without proof");
                let conf_height =
                    block_height(confirmed.get_block_hash()).expect("proof not on trunk");
                if let Some(csv) = c.derivation.csv {
                    if height >= conf_height + csv as u32 {
                        return Some(((*p).clone(), (*c).clone(), conf_height));
                    } else {
                        None
                    }
                } else {
                    return Some(((*p).clone(), (*c).clone(), conf_height));
                }
            })
            .collect()
    }

    pub fn confirmed_balance(&self) -> u64 {
        self.confirmed.values().map(|c| c.output.value).sum::<u64>()
    }

    pub fn unconfirmed_balance(&self) -> u64 {
        self.unconfirmed
            .values()
            .map(|c| c.output.value)
            .sum::<u64>()
    }

    /// unwind the tip of the trunk
    pub fn unwind_tip(&mut self, block_hash: &bitcoin::BlockHash) {
        // this means we might have lost control of coins at least temporarily
        let lost_coins = self
            .proofs
            .values()
            .filter_map(|t| {
                if *t.get_block_hash() == *block_hash {
                    Some(t.get_transaction().txid())
                } else {
                    None
                }
            })
            .flat_map(|txid| {
                self.confirmed
                    .keys()
                    .filter(move |point| point.txid == txid)
            })
            .cloned()
            .collect::<Vec<OutPoint>>();

        for point in lost_coins {
            self.proofs.remove(&point.txid);
            let coin = self.confirmed.remove(&point).unwrap();
            self.unconfirmed.insert(point, coin);
        }
    }

    /// process a block to find own coins
    /// processing should be in ascending height order, it is fine to skip blocks  if you know
    /// there is nothing in them you would care (this will be easy to tell with committed BIP158
    /// filters, but we are not yet there)
    pub fn process(&mut self, master_account: &mut MasterAccount, block: &Block) -> bool {
        let mut scripts: HashMap<Script, KeyDerivation> = master_account.get_scripts().collect();

        let mut modified = false;
        for (txnr, tx) in block.txdata.iter().enumerate() {
            if txnr > 0 {
                // skip coinbase
                for input in tx.input.iter() {
                    modified |= self.remove_confirmed(&input.previous_output);
                }
            }
            for (vout, output) in tx.output.iter().enumerate() {
                let mut lookahead = Vec::new();
                if let Some(d) = scripts.get(&output.script_pubkey) {
                    lookahead = master_account
                        .get_mut((d.account, d.sub))
                        .unwrap()
                        .do_look_ahead(Some(d.kix))
                        .unwrap()
                        .iter()
                        .map(move |(kix, s)| {
                            (
                                s.clone(),
                                KeyDerivation {
                                    kix: *kix,
                                    account: d.account,
                                    sub: d.sub,
                                    tweak: d.tweak.clone(),
                                    csv: d.csv.clone(),
                                },
                            )
                        })
                        .collect();
                    let point = OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    };
                    self.unconfirmed.remove(&point);
                    self.confirmed.insert(
                        point,
                        Coin {
                            output: output.clone(),
                            derivation: d.clone(),
                        },
                    );
                    self.proofs
                        .entry(tx.txid())
                        .or_insert(ProvedTransaction::new(block, txnr));
                    modified = true;
                }
                for (s, d) in lookahead {
                    scripts.insert(s.clone(), d);
                }
            }
        }
        modified
    }

    /// get random confirmed coins of sufficient amount
    /// returns a vector of spent outpoins, coins and their confirmation height
    pub fn choose_inputs<H>(
        &self,
        minimum: u64,
        height: u32,
        block_height: H,
    ) -> Vec<(OutPoint, Coin, u32)>
    where
        H: Fn(&bitcoin::BlockHash) -> Option<u32>,
    {
        use rand::prelude::SliceRandom;
        // TODO: knapsack
        let mut sum = 0u64;
        let mut have = self.available_coins(height, block_height);
        have.sort_by(|(_, a, _), (_, b, _)| a.output.value.cmp(&b.output.value));
        let mut inputs = Vec::new();
        for (point, coin, height) in have.iter() {
            sum += coin.output.value;
            inputs.push(((*point).clone(), (*coin).clone(), *height));
            if sum >= minimum {
                break;
            }
        }
        if sum > minimum {
            let mut change = sum - minimum;
            // drop some if possible
            while let Some(index) = inputs.iter().enumerate().find_map(|(i, (_, c, _))| {
                if c.output.value <= change {
                    Some(i)
                } else {
                    None
                }
            }) {
                let removed = inputs[index].1.output.value;
                change -= removed;
                inputs.remove(index);
            }
        }
        inputs.shuffle(&mut thread_rng());
        inputs
    }
}

#[cfg(test)]
mod test {
    use std::{
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::util::bip32::ExtendedPubKey;
    use bitcoin::{
        network::constants::Network, Address, Block, BlockHeader, OutPoint,
        Transaction, TxIn, TxOut,
    };

    use account::{Account, AccountAddressType, MasterAccount, Unlocker};
    use coins::Coins;

    const NEW_COINS: u64 = 5000000000;

    fn new_block(prev: &bitcoin::BlockHash) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                time: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32,
                nonce: 0,
                bits: 0x1d00ffff,
                prev_blockhash: prev.clone(),
                merkle_root: bitcoin::TxMerkleNode::default(),
            },
            txdata: Vec::new(),
        }
    }

    fn coin_base(miner: Address, height: u32) -> Transaction {
        Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                sequence: 0xffffffff,
                witness: Vec::new(),
                previous_output: OutPoint {
                    txid: bitcoin::Txid::default(),
                    vout: 0,
                },
                script_sig: Builder::new().push_int(height as i64).into_script(),
            }],
            output: vec![TxOut {
                value: NEW_COINS,
                script_pubkey: miner.script_pubkey(),
            }],
        }
    }

    fn add_tx(block: &mut Block, tx: Transaction) {
        block.txdata.push(tx);
        block.header.merkle_root = block.merkle_root();
    }

    fn new_master() -> MasterAccount {
        let mut master = MasterAccount::from_encrypted(
            hex::decode("e541bc73d9990b290cc4a8d8ff4592183171d1808a32695b1835aa3c12f50f34849a0dc5b730c507f19f22af393b5e5453e0974977922dbba513dadf81d364d8e204209ea02af35693b49b3b09191f01").unwrap().as_slice(),
            ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4YUqaTmpewwbvSoA4dkwzGzvwGcUbwbRyu8i6dCSroCsvFmC6qzQgJxddMfA6Mg8r6XmkJVhQ8ihAWzfRBYTG5o28AC5HWX2").unwrap(),
            1567260002);
        let mut unlocker = Unlocker::new_for_master(&master, "whatever").unwrap();
        master.add_account(
            Account::new(&mut unlocker, AccountAddressType::P2WPKH, 0, 0, 10).unwrap(),
        );
        master
    }

    fn mine(tip: &bitcoin::BlockHash, height: u32, miner: Address) -> Block {
        let mut block = new_block(tip);
        add_tx(&mut block, coin_base(miner, height));
        block
    }

    #[test]
    pub fn test_coins() {
        let mut coins = Coins::new();
        let mut master = new_master();
        let miner = master
            .get_mut((0, 0))
            .unwrap()
            .next_key()
            .unwrap()
            .address
            .clone();
        let genesis = genesis_block(Network::Testnet);
        let next = mine(&genesis.block_hash(), 1, miner);
        coins.process(&mut master, &next);
        assert_eq!(coins.confirmed_balance(), NEW_COINS);
        coins.unwind_tip(&next.block_hash());
        assert_eq!(coins.confirmed_balance(), 0);
    }
}
