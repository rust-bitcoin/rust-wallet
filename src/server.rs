use bitcoin::{
    network::{
        serialize::{serialize, deserialize},
    },
    blockdata::{
        block::Block,
        transaction::OutPoint,
    },
    util::hash::Sha256dHash,
};
use protobuf::RepeatedField;
use grpc;
use tls_api_native_tls;
use crossbeam;
use zmq;
use bitcoin_rpc_client::{BitcoinRpcApi, SerializedRawTransaction};

use std::{
    error::Error,
    time::Duration,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender, Receiver},
    },
};

use walletrpc_grpc::{Wallet, WalletServer, WalletClient};
use walletrpc::{NewAddressRequest, NewAddressResponse, NewChangeAddressRequest, NewChangeAddressResponse,
                GetUtxoListRequest, GetUtxoListResponse, SyncWithTipRequest, SyncWithTipResponse,
                MakeTxRequest, MakeTxResponse, SendCoinsRequest, SendCoinsResponse,
                WalletBalanceRequest, WalletBalanceResponse, AddressType, Utxo as RpcUtxo, OutPoint as RpcOutPoint,
                UnlockCoinsRequest, UnlockCoinsResponse, ShutdownRequest, ShutdownResponse};
use accountfactory::{AccountFactory, WalletConfig, BitcoindConfig, LockId};

pub const DEFAULT_WALLET_RPC_PORT: u16 = 5051;

fn grpc_error<T: Send>(resp: Result<T, Box<Error>>) -> grpc::SingleResponse<T> {
    match resp {
        Ok(resp) => grpc::SingleResponse::completed(resp),
        Err(e)   => grpc::SingleResponse::err(grpc::Error::Panic(e.to_string())),
    }
}

struct WalletImpl(Arc<RwLock<AccountFactory>>, Arc<AtomicBool>);

impl WalletImpl {
    fn new_address_helper(&self, req: &NewAddressRequest) -> Result<NewAddressResponse, Box<Error>> {
        let mut resp = NewAddressResponse::new();
        let mut ac = self.0.write().unwrap();
        let account = ac.get_account_mut(req.get_addr_type().into());
        let addr = account.new_address()?;
        resp.set_address(addr);
        Ok(resp)
    }

    fn new_change_address(&self, req: &NewChangeAddressRequest) -> Result<NewChangeAddressResponse, Box<Error>> {
        let mut resp = NewChangeAddressResponse::new();
        let mut ac = self.0.write().unwrap();
        let account = ac.get_account_mut(req.get_addr_type().into());
        let addr = account.new_change_address()?;
        resp.set_address(addr);
        Ok(resp)
    }

    fn make_tx_helper(&self, req: MakeTxRequest) -> Result<MakeTxResponse, Box<Error>> {
        let ops = match req.auto {
            true => {
                let ops = {
                    let utxo_list = self.0.read().unwrap().get_utxo_list();
                    let mut ops = Vec::new();
                    for utxo in &utxo_list {
                        ops.push(utxo.out_point);
                    }
                    ops
                };
                ops
            },
            false => {
                let mut ops = Vec::new();
                for op in req.ops.into_vec() {
                    ops.push(OutPoint{
                        txid: Sha256dHash::from(op.txid.as_slice()),
                        vout: op.vout,
                    })
                }
                ops
            },
        };

        let tx = self.0.write().unwrap().make_tx(ops, req.dest_addr, req.amt)?;

        // println!("{}", hex::encode(serialize(&tx).unwrap()));

        if req.submit {
            self.0.read().unwrap().client.send_raw_transaction(SerializedRawTransaction::from(tx.clone())).unwrap().unwrap();
        }

        let mut resp = MakeTxResponse::new();
        resp.set_serialized_raw_tx(serialize(&tx)?);
        Ok(resp)
    }

    fn send_coins_helper(&self, req: SendCoinsRequest) -> Result<SendCoinsResponse, Box<Error>> {
        let (tx, lock_id) = self.0.write().unwrap().send_coins(req.dest_addr, req.amt, req.lock_coins, req.witness_only)?;

        // println!("{}", hex::encode(serialize(&tx).unwrap()));

        if req.submit {
            self.0.read().unwrap().client.send_raw_transaction(SerializedRawTransaction::from(tx.clone())).unwrap().unwrap();
        }

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
        let utxo_list = self.0.read().unwrap().get_utxo_list();
        resp.set_utxos(RepeatedField::from_vec(utxo_list.into_iter().map(|utxo| utxo.into()).collect()));
        grpc::SingleResponse::completed(resp)
    }

    fn wallet_balance(&self, _m: ::grpc::RequestOptions, _req: WalletBalanceRequest) -> grpc::SingleResponse<WalletBalanceResponse> {
        info!("wallet balance was requested");
        let mut resp = WalletBalanceResponse::new();
        let balance = self.0.read().unwrap().wallet_balance();
        resp.set_total_balance(balance);
        grpc::SingleResponse::completed(resp)
    }

    fn sync_with_tip(&self, _m: grpc::RequestOptions, _req: SyncWithTipRequest) -> grpc::SingleResponse<SyncWithTipResponse> {
        info!("manual(not ZMQ) sync with tip was requested");

        let resp = SyncWithTipResponse::new();
        self.0.write().unwrap().sync_with_tip();
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
        self.0.write().unwrap().unlock_coins(LockId::from(req.lock_id));

        let resp = UnlockCoinsResponse::new();
        grpc::SingleResponse::completed(resp)
    }

    fn shutdown(&self, _m: grpc::RequestOptions, _req: ShutdownRequest) -> grpc::SingleResponse<ShutdownResponse> {
        info!("shutdown was requested");

        self.1.store(true, Ordering::Relaxed);

        let resp = ShutdownResponse::new();
        grpc::SingleResponse::completed(resp)
    }
}

pub fn launch_server(wc: WalletConfig, cfg: BitcoindConfig, wallet_rpc_port: u16) {
    let ac = AccountFactory::new_no_random(wc, cfg.clone()).unwrap();

    let rw_lock_ac = Arc::new(RwLock::new(ac));
    let shutdown = Arc::new(AtomicBool::new(false));

    let mut server: grpc::ServerBuilder<tls_api_native_tls::TlsAcceptor> = grpc::ServerBuilder::new();
    server.http.set_port(wallet_rpc_port);
    let wallet_impl = WalletImpl(Arc::clone(&rw_lock_ac), Arc::clone(&shutdown));
    server.add_service(WalletServer::new_service_def(wallet_impl));
    server.http.set_cpu_pool_threads(1);
    server.http.set_addr(format!("127.0.0.1:{}", DEFAULT_WALLET_RPC_PORT)).unwrap();
    let _server = server.build().expect("server");

    use std::thread;

    info!("wallet server started on port {} {}",
             wallet_rpc_port, "without tls" );

    crossbeam::scope(|scope| {
        scope.spawn(|| {
            info!("Connecting to bitcoind server...\n");

            let context = zmq::Context::new();
            let socket = context.socket(zmq::SUB).unwrap();

            socket.set_subscribe(b"rawblock").unwrap();

            assert!(socket.connect(&cfg.zmq_pub_raw_block).is_ok());

            let (sender, receiver): (Sender<zmq::Message>, Receiver<zmq::Message>) = mpsc::channel();
            thread::spawn(move || {
                loop {
                    let mut msg = zmq::Message::new().unwrap();
                    socket.recv(&mut msg, 0).unwrap();
                    // TODO(evg): better error handling
                    if sender.send(msg).is_err() {
                        break;
                    }
                }
            });

            let mut request_nbr = 0;
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    info!("Gracefully shutdown...");
                    break;
                }

                loop {
                    if let Ok(msg) = receiver.try_recv() {
                        if request_nbr % 3 == 0 || request_nbr % 3 == 2 {
                            info!("Received message {:?}: {}", msg.as_str(), request_nbr);
                        } else {
                            let block: Block = deserialize(&*msg).unwrap();
                            info!("Received new block");

                            let mut guarded_ac = rw_lock_ac.write().unwrap();
                            guarded_ac.process_wire_block(block);
                        }

                        request_nbr += 1;
                    } else {
                        break;
                    }
                }

                thread::sleep(Duration::from_millis(50));
            }
        });
    });
}

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

    pub fn new_address(&self, addr_type: AddressType) -> String {
        let mut req = NewAddressRequest::new();
        req.set_addr_type(addr_type);

        let resp = self.client.new_address(grpc::RequestOptions::new(), req);
        resp.wait().unwrap().1.address
    }

    pub fn new_change_address(&self, addr_type: AddressType) -> String {
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

    pub fn sync_with_tip(&self) {
        let req = SyncWithTipRequest::new();
        let resp = self.client.sync_with_tip(grpc::RequestOptions::new(), req);
        resp.wait().unwrap();
    }

    pub fn make_tx(&self, auto: bool, ops: Vec<RpcOutPoint>, dest_addr: String, amt: u64, submit: bool) -> Vec<u8> {
//        TODO(evg): smth better?
//        let mut vec = Vec::new();
//        for op in &ops {
//            let mut item = RpcOutPoint::new();
//            item.set_txid(op.txid.into_bytes().to_vec());
//            item.set_vout(op.vout);
//            vec.push(item);
//        }

        let mut req = MakeTxRequest::new();
        req.set_auto(auto);
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

    pub fn shutdown(&self) {
        let req = ShutdownRequest::new();
        let resp = self.client.shutdown(grpc::RequestOptions::new(), req);
        resp.wait().unwrap();
    }
}