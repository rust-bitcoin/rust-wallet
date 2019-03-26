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

use clap::{Arg, App};
use bitcoin_rpc_client::BitcoinCoreClient;

use std::str::FromStr;

use bitcoin_core_io::BitcoinCoreIO;
use wallet::{
    walletlibrary::{
        WalletConfig, BitcoindConfig, WalletLibraryMode, KeyGenConfig,
        DEFAULT_NETWORK, DEFAULT_PASSPHRASE, DEFAULT_SALT, DEFAULT_DB_PATH,
        DEFAULT_BITCOIND_RPC_CONNECT, DEFAULT_BITCOIND_RPC_USER, DEFAULT_BITCOIND_RPC_PASSWORD,
        DEFAULT_ZMQ_PUB_RAW_BLOCK_ENDPOINT, DEFAULT_ZMQ_PUB_RAW_TX_ENDPOINT,
    },
    default::WalletWithTrustedFullNode,
    electrumx::ElectrumxWallet,
    interface::Wallet,
};
use rust_wallet_grpc::server::{launch_server_new, DEFAULT_WALLET_RPC_PORT};

fn main() {
    let default_wallet_rpc_port_str: &str = &DEFAULT_WALLET_RPC_PORT.to_string();

    let matches = App::new("wallet")
        .version("1.0")
        .arg(
            Arg::with_name("log_level")
                .long("log_level")
                .help("should be one of ERROR, WARN, INFO, DEBUG, TRACE")
                .takes_value(true)
                .default_value("INFO"),
        )
        .arg(
            Arg::with_name("db_path")
                .long("db_path")
                .help("path to file with wallet data")
                .takes_value(true)
                .default_value(DEFAULT_DB_PATH),
        )
        .arg(
            Arg::with_name("connect")
                .long("connect")
                .help("address of bitcoind's rpc server")
                .takes_value(true)
                .default_value(DEFAULT_BITCOIND_RPC_CONNECT),
        )
        .arg(
            Arg::with_name("user")
                .long("user")
                .help("bitcoind's rpc user")
                .takes_value(true)
                .default_value(DEFAULT_BITCOIND_RPC_USER),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .help("bitcoind's rpc password")
                .takes_value(true)
                .default_value(DEFAULT_BITCOIND_RPC_PASSWORD),
        )
        .arg(
            Arg::with_name("zmqpubrawblock")
                .long("zmqpubrawblock")
                .help("address of bitcoind's zmqpubrawblock endpoint")
                .takes_value(true)
                .default_value(DEFAULT_ZMQ_PUB_RAW_BLOCK_ENDPOINT),
        )
        .arg(
            Arg::with_name("zmqpubrawtx")
                .long("zmqpubrawtx")
                .help("address of bitcoind's zmqpubrawtx endpoint")
                .takes_value(true)
                .default_value(DEFAULT_ZMQ_PUB_RAW_TX_ENDPOINT),
        )
        .arg(
            Arg::with_name("wallet_rpc_port")
                .long("wallet_rpc_port")
                .help("port of wallet's grpc server")
                .takes_value(true)
                .default_value(default_wallet_rpc_port_str),
        )
        .arg(Arg::with_name("electrumx").long("electrumx"))
        .get_matches();

    let log_level = {
        let rez = matches.value_of("log_level").unwrap();
        let rez = log::Level::from_str(rez).unwrap();
        rez
    };
    simple_logger::init_with_level(log_level).unwrap();

    let wc = WalletConfig::new(
        DEFAULT_NETWORK,
        DEFAULT_PASSPHRASE.to_string(),
        DEFAULT_SALT.to_string(),
        matches.value_of("db_path").unwrap().to_string(),
    );

    let cfg = BitcoindConfig::new(
        matches.value_of("connect").unwrap().to_string(),
        matches.value_of("user").unwrap().to_string(),
        matches.value_of("password").unwrap().to_string(),
        matches.value_of("zmqpubrawblock").unwrap().to_string(),
        matches.value_of("zmqpubrawtx").unwrap().to_string(),
    );

    // TODO(evg): rewrite it; add --create param; use WalletLibraryMode::Decrypt mode as well
    let wallet: Box<dyn Wallet + Send> = if matches.is_present("electrumx") {
        let (electrumx_wallet, mnemonic) =
            ElectrumxWallet::new(wc, WalletLibraryMode::Create(KeyGenConfig::default())).unwrap();
        println!("{}", mnemonic.to_string());
        Box::new(electrumx_wallet)
    } else {
        let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(
            &cfg.url,
            &cfg.user,
            &cfg.password,
        )));
        let (default_wallet, mnemonic) = WalletWithTrustedFullNode::new(
            wc,
            bio,
            WalletLibraryMode::Create(KeyGenConfig::default()),
        )
        .unwrap();
        println!("{}", mnemonic.to_string());
        Box::new(default_wallet)
    };

    let wallet_rpc_port: u16 = matches
        .value_of("wallet_rpc_port")
        .unwrap()
        .parse()
        .unwrap();
    launch_server_new(wallet, wallet_rpc_port);
}
