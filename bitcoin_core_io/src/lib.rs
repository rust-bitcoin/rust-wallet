extern crate bitcoin;
extern crate bitcoin_rpc_client;
extern crate wallet;

use bitcoin::{
    Block, BlockHeader, Transaction,
    util::hash::Sha256dHash,
};
use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, SerializedRawTransaction};
use wallet::interface::BlockChainIO;

pub struct BitcoinCoreIO(BitcoinCoreClient);

impl BitcoinCoreIO {
    pub fn new(client: BitcoinCoreClient) -> Self {
        BitcoinCoreIO(client)
    }
}

impl BlockChainIO for BitcoinCoreIO {
    fn get_block_count(&self) -> u32 {
        self.0.get_block_count()
            .unwrap()
            .unwrap()
            .into()
    }

    fn get_block_hash(&self, height: u32) -> Sha256dHash {
        self.0.get_block_hash(height)
            .unwrap()
            .unwrap()
    }

    fn get_block(&self, header_hash: &Sha256dHash) -> Block {
        let block = self.0.get_block(header_hash)
            .unwrap()
            .unwrap();

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
            let tx_hex = self.0.get_raw_transaction_serialized(&txid)
                .unwrap()
                .unwrap();
            let tx: Transaction = Transaction::from(tx_hex);
            txdata.push(tx);
        }

        Block {
            header,
            txdata,
        }
    }

    fn send_raw_transaction(&self, tx: &Transaction) {
        self.0.send_raw_transaction(SerializedRawTransaction::from(tx.clone())).unwrap().unwrap();
    }
}