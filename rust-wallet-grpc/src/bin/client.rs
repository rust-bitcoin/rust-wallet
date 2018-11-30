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
extern crate grpc;
extern crate tls_api;
extern crate tls_api_native_tls;
extern crate clap;
extern crate wallet;
extern crate rust_wallet_grpc;

use clap::{Arg, App, SubCommand};

use wallet::account::AccountAddressType;
use rust_wallet_grpc::{
    server::DEFAULT_WALLET_RPC_PORT,
    client::WalletClientWrapper,
};

fn main() {
    let default_wallet_rpc_port_str: &str = &DEFAULT_WALLET_RPC_PORT.to_string();

    let matches = App::new("walletcli")
        .version("1.0")
        .arg(Arg::with_name("wallet_rpc_port")
            .long("wallet_rpc_port")
            .help("port of wallet's grpc server")
            .takes_value(true)
            .default_value(default_wallet_rpc_port_str))
        .subcommand(SubCommand::with_name("newaddress")
            .arg(Arg::with_name("addr_type")
                .long("addr_type")
                .takes_value(true)
                .default_value("p2wkh")))
        .subcommand(SubCommand::with_name("get_utxo_list"))
        .subcommand(SubCommand::with_name("walletbalance"))
        .subcommand(SubCommand::with_name("sync_with_tip"))
        .subcommand(SubCommand::with_name("send_coins")
            .arg(Arg::with_name("dest_addr")
                .long("dest_addr")
                .takes_value(true))
            .arg(Arg::with_name("amt")
                .long("amt")
                .takes_value(true))
            .arg(Arg::with_name("submit")
                .long("submit"))
            .arg(Arg::with_name("lock_coins")
                .long("lock_coins"))
            .arg(Arg::with_name("witness_only")
                .long("witness_only")))
        .subcommand(SubCommand::with_name("unlock_coins")
            .arg(Arg::with_name("lock_id")
                .long("lock_id")
                .takes_value(true)))
        .subcommand(SubCommand::with_name("shutdown"))
        .get_matches();

    let wallet_rpc_port: u16 = matches.value_of("wallet_rpc_port").unwrap().parse().unwrap();
    let client = WalletClientWrapper::new(wallet_rpc_port);

    if let Some(matches) = matches.subcommand_matches("newaddress") {
        let addr_type = matches.value_of("addr_type").unwrap();
        let addr_type: AccountAddressType = addr_type.into();

        let addr = client.new_address(addr_type.into());
        println!("{}", addr);
    }

    if let Some(_matches) = matches.subcommand_matches("get_utxo_list") {
        let utxo_list = client.get_utxo_list();
        println!("{:?}", utxo_list);
    }

    if let Some(_matches) = matches.subcommand_matches("walletbalance") {
        let balance = client.wallet_balance();
        println!("{:?}", balance);
    }

    if let Some(_matches) = matches.subcommand_matches("sync_with_tip") {
        client.sync_with_tip();
    }

    if let Some(matches) = matches.subcommand_matches("send_coins") {
        let dest_addr = matches.value_of("dest_addr").unwrap();
        let amt: u64 = matches.value_of("amt").unwrap().parse().unwrap();
        let submit = matches.is_present("submit");
        let lock_coins = matches.is_present("lock_coins");
        client.send_coins(dest_addr.to_string(), amt, submit, lock_coins).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("unlock_coins") {
        let lock_id: u64 = matches.value_of("lock_id").unwrap().parse().unwrap();
        client.unlock_coins(lock_id);
    }

    if let Some(_matches) = matches.subcommand_matches("shutdown") {
        client.shutdown();
    }
}
