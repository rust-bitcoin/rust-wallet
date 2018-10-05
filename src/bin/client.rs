extern crate grpc;
extern crate futures;
extern crate tls_api;
extern crate tls_api_native_tls;
extern crate clap;
extern crate wallet;

use clap::{Arg, App, SubCommand};

use wallet::{
    account::AccountAddressType,
    server::{WalletClientWrapper, DEFAULT_WALLET_RPC_PORT},
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
        .subcommand(SubCommand::with_name("make_tx")
            .arg(Arg::with_name("auto")
                .long("auto"))
            .arg(Arg::with_name("dest_addr")
                .long("dest_addr"))
            .arg(Arg::with_name("amt")
                .long("amt")
                .takes_value(true))
            .arg(Arg::with_name("submit")
                .long("submit")))
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
                .long("lock_coins")))
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

    if let Some(matches) = matches.subcommand_matches("make_tx") {
        let auto = matches.is_present("auto");
        let dest_addr = matches.value_of("dest_addr").unwrap().to_string();
        let amt: u64 = matches.value_of("amt").unwrap().parse().unwrap();
        let submit = matches.is_present("submit");
        client.make_tx(auto, Vec::new(), dest_addr, amt, submit);
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
