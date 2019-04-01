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
use bitcoin::{Block, Transaction, OutPoint};

use std::error::Error;

use super::walletlibrary::{WalletLibrary, WalletConfig, LockId, WalletLibraryMode};
use super::interface::{BlockChainIO, WalletLibraryInterface, Wallet};
use super::error::WalletError;
use super::mnemonic::Mnemonic;

// a factory for TREZOR (BIP44) compatible accounts
pub struct WalletWithTrustedFullNode<IO>
where
    IO: BlockChainIO,
{
    pub wallet_lib: Box<dyn WalletLibraryInterface + Send>,
    bio: IO,
}

impl<IO> Wallet for WalletWithTrustedFullNode<IO>
where
    IO: BlockChainIO,
{
    fn wallet_lib(&self) -> &Box<dyn WalletLibraryInterface + Send> {
        &self.wallet_lib
    }

    fn wallet_lib_mut(&mut self) -> &mut Box<dyn WalletLibraryInterface + Send> {
        &mut self.wallet_lib
    }

    fn reconnect(&mut self) {}

    fn send_coins(
        &mut self,
        addr_str: String,
        amt: u64,
        lock_coins: bool,
        witness_only: bool,
        submit: bool,
    ) -> Result<(Transaction, LockId), Box<dyn Error>> {
        let (tx, lock_id) = self
            .wallet_lib
            .send_coins(addr_str, amt, lock_coins, witness_only)?;
        if submit {
            self.bio.send_raw_transaction(&tx)?;
        }
        Ok((tx, lock_id))
    }

    fn make_tx(
        &mut self,
        ops: Vec<OutPoint>,
        addr_str: String,
        amt: u64,
        submit: bool,
    ) -> Result<Transaction, Box<dyn Error>> {
        let tx = self.wallet_lib.make_tx(ops, addr_str, amt).unwrap();
        if submit {
            self.bio.send_raw_transaction(&tx)?;
        }
        Ok(tx)
    }

    fn publish_tx(&mut self, tx: &Transaction) -> Result<(), Box<dyn Error>> {
        self.bio.send_raw_transaction(tx)?;
        Ok(())
    }

    fn sync_with_tip(&mut self) -> Result<(), Box<dyn Error>> {
        let block_height = self.bio.get_block_count()?;

        let start_from = self.wallet_lib.get_last_seen_block_height_from_memory() + 1;
        self.process_block_range(start_from, block_height as usize)?;

        Ok(())
    }
}

impl<IO> WalletWithTrustedFullNode<IO>
where
    IO: BlockChainIO,
{
    /// initialize with new random master key
    pub fn new(
        wc: WalletConfig,
        bio: IO,
        mode: WalletLibraryMode,
    ) -> Result<(Self, Mnemonic), WalletError> {
        let (wallet_lib, mnemonic) = WalletLibrary::new(wc, mode).unwrap();

        Ok((
            WalletWithTrustedFullNode {
                wallet_lib: Box::new(wallet_lib),
                bio,
            },
            mnemonic,
        ))
    }

    fn process_block(&mut self, block_height: usize, block: &Block) {
        for tx in &block.txdata {
            self.wallet_lib.process_tx(&tx);
        }
        // TODO(evg): if block_height > self.last_seen_block_height?
        self.wallet_lib
            .update_last_seen_block_height_in_memory(block_height);

        self.wallet_lib
            .update_last_seen_block_height_in_db(block_height);
    }

    fn process_block_range(&mut self, left: usize, right: usize) -> Result<(), IO::Error> {
        for i in left..right + 1 {
            let block_hash = self.bio.get_block_hash(i as u32)?;
            let block = self.bio.get_block(&block_hash)?;
            self.process_block(i, &block);
        }

        Ok(())
    }
}
