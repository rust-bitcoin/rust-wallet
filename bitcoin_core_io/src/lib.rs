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
use bitcoin_rpc_client::{
    BitcoinCoreClient, BitcoinRpcApi,
    rpc::SerializedRawTransaction, RpcError, ClientError,
};
use wallet::interface::BlockChainIO;
use std::{fmt, error::Error};

#[derive(Debug)]
pub enum BitcoinCoreIoError {
    ClientError(ClientError),
    RpcError(RpcError),
}

impl fmt::Display for BitcoinCoreIoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &BitcoinCoreIoError::ClientError(ref e) => write!(f, "{:?}", e),
            &BitcoinCoreIoError::RpcError(ref e) => write!(f, "{:?}", e),
        }
    }
}

impl Error for BitcoinCoreIoError {
}

impl BitcoinCoreIoError {
    fn flatten<T>(r: Result<Result<T, RpcError>, ClientError>) -> Result<T, Self> {
        match r {
            Ok(Ok(t)) => Ok(t),
            Err(a) => Err(BitcoinCoreIoError::ClientError(a)),
            Ok(Err(b)) => Err(BitcoinCoreIoError::RpcError(b)),
        }
    }
}

pub struct BitcoinCoreIO(BitcoinCoreClient);

impl BitcoinCoreIO {
    pub fn new(client: BitcoinCoreClient) -> Self {
        BitcoinCoreIO(client)
    }
}

impl BlockChainIO for BitcoinCoreIO {
    type Error = BitcoinCoreIoError;

    fn get_block_count(&self) -> Result<u32, Self::Error> {
        Self::Error::flatten(self.0.get_block_count()).map(Into::into)
    }

    fn get_block_hash(&self, height: u32) -> Result<Sha256dHash, Self::Error> {
        Self::Error::flatten(self.0.get_block_hash(height))
    }

    fn get_block(&self, header_hash: &Sha256dHash) -> Result<Block, Self::Error> {
        use bitcoin_hashes::hex::FromHex;

        let &BitcoinCoreIO(ref client) = self;

        let block = Self::Error::flatten(client.get_block(header_hash))?;

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
            let tx_hex = client
                .get_raw_transaction_serialized(&txid);
            txdata.push(Self::Error::flatten(tx_hex)?.into());
        }

        Ok(Block { header, txdata })
    }

    fn send_raw_transaction(&self, tx: &Transaction) -> Result<Sha256dHash, Self::Error> {
        let v = self.0
            .send_raw_transaction(SerializedRawTransaction::from(tx.clone()));
        Self::Error::flatten(v)
    }
}
