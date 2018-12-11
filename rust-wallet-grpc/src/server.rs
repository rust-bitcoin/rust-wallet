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
    network::serialize::serialize,
    blockdata::transaction::OutPoint,
    util::hash::Sha256dHash,
};
use protobuf::RepeatedField;
use grpc;
use tls_api_native_tls;
use wallet::{
    account::{Utxo, AccountAddressType},
    walletlibrary::LockId,
    interface::Wallet as WalletInterface,
};

use std::{
    thread,
    error::Error,
    time::Duration,
    sync::{
        Arc, Mutex,
        mpsc::{self, Sender},
    },
};

use walletrpc_grpc::{Wallet, WalletServer};
use walletrpc::{NewAddressRequest, NewAddressResponse, NewChangeAddressRequest, NewChangeAddressResponse,
                GetUtxoListRequest, GetUtxoListResponse, SyncWithTipRequest, SyncWithTipResponse,
                MakeTxRequest, MakeTxResponse, SendCoinsRequest, SendCoinsResponse,
                WalletBalanceRequest, WalletBalanceResponse, AddressType as RpcAddressType, Utxo as RpcUtxo, OutPoint as RpcOutPoint,
                UnlockCoinsRequest, UnlockCoinsResponse, ShutdownRequest, ShutdownResponse};

pub const DEFAULT_WALLET_RPC_PORT: u16 = 5051;
const SHUTDOWN_TIMEOUT_IN_MS: u64 = 50;

fn grpc_error<T: Send>(resp: Result<T, Box<Error>>) -> grpc::SingleResponse<T> {
    match resp {
        Ok(resp) => grpc::SingleResponse::completed(resp),
        Err(e)   => grpc::SingleResponse::err(grpc::Error::Panic(e.to_string())),
    }
}


impl Into<RpcUtxo> for Utxo {
    fn into(self) -> RpcUtxo {
        let mut op = RpcOutPoint::new();
        op.set_txid(self.out_point.txid.into_bytes().to_vec());
        op.set_vout(self.out_point.vout);

        let mut rpc_utxo = RpcUtxo::new();
        rpc_utxo.set_value(self.value.into());
        rpc_utxo.set_out_point(op);
        rpc_utxo.set_addr_type(self.addr_type.into());
        rpc_utxo
    }
}

impl From<RpcAddressType> for AccountAddressType {
    fn from(rpc_addr_type: RpcAddressType) -> Self {
        match rpc_addr_type {
            RpcAddressType::P2PKH  => AccountAddressType::P2PKH,
            RpcAddressType::P2SHWH => AccountAddressType::P2SHWH,
            RpcAddressType::P2WKH  => AccountAddressType::P2WKH,
        }
    }
}

impl Into<RpcAddressType> for AccountAddressType {
    fn into(self) -> RpcAddressType {
        match self {
            AccountAddressType::P2PKH  => RpcAddressType::P2PKH,
            AccountAddressType::P2SHWH => RpcAddressType::P2SHWH,
            AccountAddressType::P2WKH  => RpcAddressType::P2WKH,
        }
    }
}

struct ShutdownSignal;

struct WalletImpl {
    af: Arc<Mutex<Box<WalletInterface + Send>>>,
    shutdown: Mutex<Sender<ShutdownSignal>>,
}

impl WalletImpl {
    fn new(af: Arc<Mutex<Box<WalletInterface + Send>>>, shutdown: Mutex<Sender<ShutdownSignal>>) -> Self {
        Self {
            af,
            shutdown,
        }
    }

    fn new_address_helper(&self, req: &NewAddressRequest) -> Result<NewAddressResponse, Box<Error>> {
        let mut resp = NewAddressResponse::new();
        let mut ac = self.af.lock().unwrap();
        let account = ac.wallet_lib_mut().get_account_mut(req.get_addr_type().into());
        let addr = account.new_address()?;
        resp.set_address(addr);
        Ok(resp)
    }

    fn new_change_address(&self, req: &NewChangeAddressRequest) -> Result<NewChangeAddressResponse, Box<Error>> {
        let mut resp = NewChangeAddressResponse::new();
        let mut ac = self.af.lock().unwrap();
        let account = ac.wallet_lib_mut().get_account_mut(req.get_addr_type().into());
        let addr = account.new_change_address()?;
        resp.set_address(addr);
        Ok(resp)
    }

    fn make_tx_helper(&self, req: MakeTxRequest) -> Result<MakeTxResponse, Box<Error>> {
        let mut ops = Vec::new();
        for op in req.ops.into_vec() {
            ops.push(OutPoint{
                txid: Sha256dHash::from(op.txid.as_slice()),
                vout: op.vout,
            })
        }

        let tx = self.af.lock().unwrap().make_tx(ops, req.dest_addr, req.amt, req.submit)?;

        let mut resp = MakeTxResponse::new();
        resp.set_serialized_raw_tx(serialize(&tx)?);
        Ok(resp)
    }

    fn send_coins_helper(&self, req: SendCoinsRequest) -> Result<SendCoinsResponse, Box<Error>> {
        let (tx, lock_id) = self.af.lock().unwrap().send_coins(req.dest_addr, req.amt, req.lock_coins, req.witness_only, req.submit)?;

        let mut resp = SendCoinsResponse::new();
        resp.set_serialized_raw_tx(serialize(&tx).unwrap());
        if req.lock_coins {
            resp.set_lock_id(lock_id.into());
        }
        Ok(resp)
    }
}

impl Wallet for WalletImpl {
    fn new_address(&self, _m: grpc::RequestOptions, req: NewAddressRequest) -> grpc::SingleResponse<NewAddressResponse> {
        info!("new {:?} address was requested", req.addr_type);
        grpc_error(self.new_address_helper(&req))
    }

    fn new_change_address(&self, _m: grpc::RequestOptions, req: NewChangeAddressRequest) -> grpc::SingleResponse<NewChangeAddressResponse> {
        info!("new {:?} change address was requested", req.addr_type);
        grpc_error(self.new_change_address(&req))
    }

    fn get_utxo_list(&self, _m: grpc::RequestOptions, _req: GetUtxoListRequest) -> grpc::SingleResponse<GetUtxoListResponse> {
        info!("utxo list was requested");
        let mut resp = GetUtxoListResponse::new();
        let utxo_list = self.af.lock().unwrap().wallet_lib().get_utxo_list();
        resp.set_utxos(RepeatedField::from_vec(utxo_list.into_iter().map(|utxo| utxo.into()).collect()));
        grpc::SingleResponse::completed(resp)
    }

    fn wallet_balance(&self, _m: ::grpc::RequestOptions, _req: WalletBalanceRequest) -> grpc::SingleResponse<WalletBalanceResponse> {
        info!("wallet balance was requested");
        let mut resp = WalletBalanceResponse::new();
        let balance = self.af.lock().unwrap().wallet_lib().wallet_balance();
        resp.set_total_balance(balance);
        grpc::SingleResponse::completed(resp)
    }

    fn sync_with_tip(&self, _m: grpc::RequestOptions, _req: SyncWithTipRequest) -> grpc::SingleResponse<SyncWithTipResponse> {
        info!("manual(not ZMQ) sync with tip was requested");

        let resp = SyncWithTipResponse::new();
        self.af.lock().unwrap().sync_with_tip();
        grpc::SingleResponse::completed(resp)
    }

    fn make_tx(&self, _m: grpc::RequestOptions, req: MakeTxRequest) -> grpc::SingleResponse<MakeTxResponse> {
        info!("make_tx was requested");
        grpc_error(self.make_tx_helper(req))
    }

    fn send_coins(&self, _m: grpc::RequestOptions, req: SendCoinsRequest) -> grpc::SingleResponse<SendCoinsResponse> {
        info!("send_coins was requested");
        grpc_error(self.send_coins_helper(req))
    }

    fn unlock_coins(&self, _m: grpc::RequestOptions, req: UnlockCoinsRequest) -> grpc::SingleResponse<UnlockCoinsResponse> {
        info!("unlock_coins was requested");
        self.af.lock().unwrap().wallet_lib_mut().unlock_coins(LockId::from(req.lock_id));

        let resp = UnlockCoinsResponse::new();
        grpc::SingleResponse::completed(resp)
    }

    fn shutdown(&self, _m: grpc::RequestOptions, _req: ShutdownRequest) -> grpc::SingleResponse<ShutdownResponse> {
        info!("shutdown was requested");

        self.shutdown.lock().unwrap().send(ShutdownSignal).unwrap();

        let resp = ShutdownResponse::new();
        grpc::SingleResponse::completed(resp)
    }
}

pub fn launch_server_new(wallet: Box<WalletInterface + Send>, wallet_rpc_port: u16) {
    let wallet = Arc::new(Mutex::new(wallet));

    let (shutdown_sender, shutdown_receiver) = mpsc::channel();

    let mut server: grpc::ServerBuilder<tls_api_native_tls::TlsAcceptor> = grpc::ServerBuilder::new();
    server.http.set_port(wallet_rpc_port);
    let wallet_impl = WalletImpl::new(wallet, Mutex::new(shutdown_sender));
    server.add_service(WalletServer::new_service_def(wallet_impl));
    server.http.set_cpu_pool_threads(1);
    server.http.set_addr(format!("127.0.0.1:{}", DEFAULT_WALLET_RPC_PORT)).unwrap();
    let _server = server.build().expect("server");

    info!("wallet server started on port {} {}",
          wallet_rpc_port, "without tls" );

    // wait for shutdown signal from grpc client
    shutdown_receiver.recv().unwrap();

    // give some time to server gracefully shutdown
    thread::sleep(Duration::from_millis(SHUTDOWN_TIMEOUT_IN_MS));
}