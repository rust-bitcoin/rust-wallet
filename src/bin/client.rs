extern crate grpc;
extern crate futures;
extern crate wallet;

extern crate tls_api;
extern crate tls_api_native_tls;

extern crate clap;
use clap::{Arg, App, SubCommand};

use std::env;
use std::sync::Arc;
use std::net::SocketAddr;

use wallet::walletrpc_grpc::{Wallet, WalletClient};
use wallet::walletrpc::{NewAddressRequest, AddressType as RpcAddressType, GetUtxoListRequest, SyncWithTipRequest, MakeTxRequest};
use wallet::account::AccountAddressType;

use tls_api::TlsConnectorBuilder;
use tls_api::TlsConnector;

fn main() {
    let name = "world";

    let matches = App::new("walletcli")
        .version("1.0")
        .subcommand(SubCommand::with_name("newaddress")
            .arg(Arg::with_name("addr_type")
                .long("addr_type")
                .takes_value(true)
                .default_value("p2wkh")))
        .subcommand(SubCommand::with_name("get_utxo_list"))
        .subcommand(SubCommand::with_name("sync_with_tip"))
        .subcommand(SubCommand::with_name("make_tx"))
        .get_matches();

    let port = 50051;

    let client_conf = Default::default();

    let client = WalletClient::new_plain("::1", port, client_conf).unwrap();

    if let Some(matches) = matches.subcommand_matches("newaddress") {
        let addr_type = matches.value_of("addr_type").unwrap();

        let mut req = NewAddressRequest::new();
        let addr_type: AccountAddressType = addr_type.into();
        req.set_addr_type(addr_type.into());
        let resp = client.new_address(grpc::RequestOptions::new(), req);
        println!("{:?}", resp.wait().unwrap().1);
    }

    if let Some(matches) = matches.subcommand_matches("get_utxo_list") {
        let mut req = GetUtxoListRequest::new();
        let resp = client.get_utxo_list(grpc::RequestOptions::new(), req);
        println!("{:?}", resp.wait().unwrap().1);
    }

    if let Some(matches) = matches.subcommand_matches("sync_with_tip") {
        let mut req = SyncWithTipRequest::new();
        let resp = client.sync_with_tip(grpc::RequestOptions::new(), req);
        println!("{:?}", resp.wait().unwrap().1);
    }

    if let Some(matches) = matches.subcommand_matches("make_tx") {
        let req = MakeTxRequest::new();
        let resp = client.make_tx(grpc::RequestOptions::new(), req);
        println!("{:?}", resp.wait().unwrap().1);
    }
}
