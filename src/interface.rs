pub trait Wallet {
    fn get_account(&self, address_type: AccountAddressType) -> Arc<RwLock<Account>>;
    fn wallet_balance(&self) -> u64;
    fn get_utxo_list(&self) -> Vec<Utxo>;
    fn unlock_coins(&mut self, lock_id: LockId);
    fn send_coins(
        &mut self,
        addr_str: String,
        amt: u64,
        lock_coins: bool,
        witness_only: bool,
    ) -> Result<(BitcoinTransaction, LockId), Box<Error>>;
    fn make_tx(
        &mut self,
        ops: Vec<OutPoint>,
        addr_str: String,
        amt: u64,
    ) -> Result<BitcoinTransaction, Box<Error>>;
    fn process_wire_block(&mut self, block: WireBlock);
}

pub trait Account {
    fn new_address(&mut self) -> Result<String, Box<Error>>;
    fn new_change_address(&mut self) -> Result<String, Box<Error>>;
}