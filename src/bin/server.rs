extern crate futures;

extern crate wallet;
extern crate grpc;
extern crate protobuf;
extern crate tls_api;
extern crate tls_api_native_tls;

extern crate bitcoin;
extern crate hex;
extern crate crossbeam;

extern crate zmq;

use bitcoin::network::serialize::deserialize;
use bitcoin::blockdata::block::Block;

use std::thread;
use std::env;
use std::sync::{Arc, RwLock};

use bitcoin::network::constants::Network;
use bitcoin::network::serialize::serialize;

use wallet::walletrpc_grpc::{Wallet, WalletServer};
use wallet::walletrpc::{NewAddressRequest, NewAddressResponse, GetUtxoListRequest, GetUtxoListResponse,
                        SyncWithTipRequest, SyncWithTipResponse, MakeTxRequest, MakeTxResponse};
use wallet::account::AccountAddressType;
use wallet::accountfactory::{AccountFactory, BitcoindConfig};
use wallet::keyfactory::MasterKeyEntropy;

use tls_api::TlsAcceptorBuilder;
use protobuf::RepeatedField;

struct WalletImpl(Arc<RwLock<AccountFactory>>);

impl Wallet for WalletImpl {
    fn new_address(&self, _m: grpc::RequestOptions, req: NewAddressRequest) -> grpc::SingleResponse<NewAddressResponse> {
        let mut r = NewAddressResponse::new();
        let guarded = self.0.read().unwrap().get_account(req.get_addr_type().into());
        let addr = guarded.write().unwrap().new_address().unwrap();
        r.set_address(addr);
        grpc::SingleResponse::completed(r)
    }

    fn get_utxo_list(&self, _m: grpc::RequestOptions, req: GetUtxoListRequest) -> grpc::SingleResponse<GetUtxoListResponse> {
        let mut resp = GetUtxoListResponse::new();
        let utxo_list = self.0.read().unwrap().get_utxo_list();
        resp.set_utxos(RepeatedField::from_vec(utxo_list.into_iter().map(|utxo| utxo.into()).collect()));
        grpc::SingleResponse::completed(resp)
    }

    fn sync_with_tip(&self, _m: grpc::RequestOptions, req: SyncWithTipRequest) -> grpc::SingleResponse<SyncWithTipResponse> {
        let mut resp = SyncWithTipResponse::new();
        self.0.write().unwrap().sync_with_tip();
        grpc::SingleResponse::completed(resp)
    }

    fn make_tx(&self, _m: grpc::RequestOptions, req: MakeTxRequest) -> grpc::SingleResponse<MakeTxResponse> {
        let ops = {
            let utxo_list = self.0.read().unwrap().get_utxo_list();
            let mut ops = Vec::new();
            for utxo in &utxo_list {
                ops.push(utxo.out_point);
            }
            ops
        };

        let p2wkh_addr = {
            let guarded = self.0.write().unwrap().get_account(AccountAddressType::P2WKH);
            let mut p2wkh_account = guarded.write().unwrap();
            let p2wkh_addr = p2wkh_account.new_address().unwrap();
            p2wkh_addr
        };

        let tx = self.0.read().unwrap().make_tx(ops, p2wkh_addr);

        println!("{}", hex::encode(serialize(&tx).unwrap()));

        let resp = MakeTxResponse::new();
        grpc::SingleResponse::completed(resp)
    }
}

fn main() {
    let cfg = BitcoindConfig::new(
        "http://127.0.0.1:18332".to_owned(),
        "user".to_owned(),
        "password".to_owned(),
    );

    let mut ac = AccountFactory::new_no_random(MasterKeyEntropy::Recommended,
                                               Network::Regtest, "", "easy", cfg).unwrap();
    ac.initialize();

    let rw_lock_ac = Arc::new(RwLock::new(ac));

    let port = 50051;

    let mut server: grpc::ServerBuilder<tls_api_native_tls::TlsAcceptor> = grpc::ServerBuilder::new();
    server.http.set_port(port);
    let wallet_impl = WalletImpl(Arc::clone(&rw_lock_ac));
    server.add_service(WalletServer::new_service_def(wallet_impl));
    server.http.set_cpu_pool_threads(1);
    let _server = server.build().expect("server");

    use std::thread;

    println!("wallet server started on port {} {}",
             port, "without tls" );

    crossbeam::scope(|scope| {
        scope.spawn(|| {
            println!("Connecting to bitcoind server...\n");

            let context = zmq::Context::new();
            let socket = context.socket(zmq::SUB).unwrap();

            socket.set_subscribe(b"rawblock").unwrap();

            assert!(socket.connect("tcp://localhost:18501").is_ok());

            let mut msg = zmq::Message::new().unwrap();

            for request_nbr in 0..1000 {
                socket.recv(&mut msg, 0).unwrap();
                if request_nbr % 3 == 0 || request_nbr % 3 == 2 {
                    println!("Received message {:?}: {}", msg.as_str(), request_nbr);
                } else {
                    let block: Block = deserialize(&*msg).unwrap();
                    println!("{:?}", block);

                    let mut guarded_ac = rw_lock_ac.write().unwrap();
                    guarded_ac.process_wire_block(block);
                }
            }
        });

        scope.spawn(|| {
            loop {
                thread::park();
            }
        });
    });
}