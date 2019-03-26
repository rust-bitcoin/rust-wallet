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
    Block, BlockHeader, Transaction,
};
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, rpc::SerializedRawTransaction};
use wallet::interface::BlockChainIO;

pub struct BitcoinCoreIO(BitcoinCoreClient);

impl BitcoinCoreIO {
    pub fn new(client: BitcoinCoreClient) -> Self {
        BitcoinCoreIO(client)
    }
}

impl BlockChainIO for BitcoinCoreIO {
    fn get_block_count(&self) -> u32 {
        self.0.get_block_count().unwrap().unwrap().into()
    }

    fn get_block_hash(&self, height: u32) -> Sha256dHash {
        self.0.get_block_hash(height).unwrap().unwrap()
    }

    fn get_block(&self, header_hash: &Sha256dHash) -> Block {
        use bitcoin_hashes::hex::FromHex;

        let block = self.0.get_block(header_hash).unwrap().unwrap();

        // TODO(evg): review it
        let header = BlockHeader {
            version: block.version,
            prev_blockhash: block.previousblockhash.unwrap(),
            merkle_root: Sha256dHash::from_hex(&block.merkleroot).unwrap(),
            time: block.time as u32,
            bits: 0,
            nonce: block.nonce,
        };
        let mut txdata = Vec::new();
        for txid in &block.tx {
            let tx_hex = self
                .0
                .get_raw_transaction_serialized(&txid)
                .unwrap()
                .unwrap();
            let tx: Transaction = tx_hex.into();
            txdata.push(tx);
        }

        Block { header, txdata }
    }

    fn send_raw_transaction(&self, tx: &Transaction) {
        self.0
            .send_raw_transaction(SerializedRawTransaction::from(tx.clone()))
            .unwrap()
            .unwrap();
    }
}
