use protobuf::RepeatedField;
use grpc;

use std::error::Error;

use walletrpc_grpc::{Wallet, WalletClient};
use walletrpc::{NewAddressRequest, NewChangeAddressRequest, GetUtxoListRequest, WalletBalanceRequest,
                MakeTxRequest, SendCoinsRequest, UnlockCoinsRequest, SyncWithTipRequest, ShutdownRequest,
                AddressType as RpcAddressType, Utxo as RpcUtxo, OutPoint as RpcOutPoint};

pub struct WalletClientWrapper {
    client: WalletClient,
}

impl WalletClientWrapper {
    pub fn new(port: u16) -> WalletClientWrapper {
        // let port = 50051;
        let client_conf = Default::default();
        let client = WalletClient::new_plain("127.0.0.1", port, client_conf).unwrap();
        WalletClientWrapper { client }
    }

    pub fn new_address(&self, addr_type: RpcAddressType) -> String {
        let mut req = NewAddressRequest::new();
        req.set_addr_type(addr_type);

        let resp = self.client.new_address(grpc::RequestOptions::new(), req);
        resp.wait().unwrap().1.address
    }

    pub fn new_change_address(&self, addr_type: RpcAddressType) -> String {
        let mut req = NewChangeAddressRequest::new();
        req.set_addr_type(addr_type);

        let resp = self.client.new_change_address(grpc::RequestOptions::new(), req);
        resp.wait().unwrap().1.address
    }

    pub fn get_utxo_list(&self) -> Vec<RpcUtxo> {
        let req = GetUtxoListRequest::new();
        let resp = self.client.get_utxo_list(grpc::RequestOptions::new(), req);
        resp.wait().unwrap().1.utxos.into_vec()
    }

    pub fn wallet_balance(&self) -> u64 {
        let req = WalletBalanceRequest::new();
        let resp = self.client.wallet_balance(grpc::RequestOptions::new(), req);
        resp.wait().unwrap().1.total_balance
    }

    pub fn make_tx(&self, ops: Vec<RpcOutPoint>, dest_addr: String, amt: u64, submit: bool) -> Vec<u8> {
        let mut req = MakeTxRequest::new();
        req.set_ops(RepeatedField::from_vec(ops));
        req.set_dest_addr(dest_addr);
        req.set_amt(amt);
        req.set_submit(submit);
        let resp = self.client.make_tx(grpc::RequestOptions::new(), req);
        resp.wait().unwrap().1.serialized_raw_tx
    }

    pub fn send_coins(&self, dest_addr: String, amt: u64, submit: bool, lock_coins: bool) -> Result<(Vec<u8>, u64), Box<Error>> {
        let mut req = SendCoinsRequest::new();
        req.set_dest_addr(dest_addr);
        req.set_amt(amt);
        req.set_submit(submit);
        req.set_lock_coins(lock_coins);
        let resp = self.client.send_coins(grpc::RequestOptions::new(), req);
        let resp = resp.wait()?.1;
        Ok((resp.serialized_raw_tx, resp.lock_id))
    }

    pub fn unlock_coins(&self, lock_id: u64) {
        let mut req = UnlockCoinsRequest::new();
        req.set_lock_id(lock_id);

        let resp = self.client.unlock_coins(grpc::RequestOptions::new(), req);
        resp.wait().unwrap();
    }

    pub fn sync_with_tip(&self) {
        let req = SyncWithTipRequest::new();
        let resp = self.client.sync_with_tip(grpc::RequestOptions::new(), req);
        resp.wait().unwrap();
    }

    pub fn shutdown(&self) {
        let req = ShutdownRequest::new();
        let resp = self.client.shutdown(grpc::RequestOptions::new(), req);
        resp.wait().unwrap();
    }
}