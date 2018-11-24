extern crate wallet;
extern crate rust_wallet_grpc;
extern crate tc_coblox_bitcoincore;
extern crate testcontainers;
extern crate bitcoin_rpc_client;
extern crate bitcoin;
extern crate hex;
extern crate grpc;
extern crate rand;
extern crate log;
extern crate simple_logger;

use tc_coblox_bitcoincore::BitcoinCore;
use testcontainers::{
    clients::DockerCli,
    Docker, Container,
};
use bitcoin::{
    network::serialize::deserialize,
    Transaction,
};
use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, Address};
use rand::{Rng, thread_rng};

use std::{
    str::FromStr,
    thread,
    time::Duration,
};

use wallet::accountfactory::{WalletConfig, BitcoindConfig};
use rust_wallet_grpc::{
    server::{launch_server, DEFAULT_WALLET_RPC_PORT},
    client::WalletClientWrapper,
    walletrpc::{AddressType, OutPoint as RpcOutPoint},
};

const LAUNCH_SERVER_DELAY_MS: u64 = 3000;
const SHUTDOWN_SERVER_DELAY_MS: u64 = 2000;

fn bitcoind_init(node: &Container<DockerCli, BitcoinCore>) -> (BitcoinCoreClient, BitcoindConfig) {
    let host_port = node.get_host_port(18443).unwrap();
    let zmq_port = node.get_host_port(18501).unwrap();
    let url = format!("http://localhost:{}", host_port);
    let auth = node.image().auth();
    let client = BitcoinCoreClient::new(
        url.as_str(),
        auth.username(),
        auth.password(),
    );
    let cfg = BitcoindConfig::new(
        url, auth.username().to_owned(),
        auth.password().to_owned(),
        format!("tcp://localhost:{}", zmq_port),
        format!("tcp://localhost:{}", zmq_port),
    );

    (client, cfg)
}

fn launch_server_and_wait(db_path: String, cfg: BitcoindConfig) -> WalletClientWrapper {
    thread::spawn(move || {
        launch_server(WalletConfig::with_db_path(db_path), cfg, DEFAULT_WALLET_RPC_PORT);
    });
    thread::sleep(Duration::from_millis(LAUNCH_SERVER_DELAY_MS));
    let client = WalletClientWrapper::new(DEFAULT_WALLET_RPC_PORT);
    client
}

fn shutdown_and_wait(client: &WalletClientWrapper) {
    client.shutdown();
    thread::sleep(Duration::from_millis(SHUTDOWN_SERVER_DELAY_MS));
}

fn restart_wallet(client: &WalletClientWrapper, db_path: String, cfg: BitcoindConfig) {
    shutdown_and_wait(client);
    launch_server_and_wait(db_path, cfg);
}

fn tmp_db_path() -> String {
    let mut rez: String = "/tmp/test_".to_string();
    let suffix: String = thread_rng().gen_ascii_chars().take(10).collect();
    rez.push_str(&suffix);
    rez
}

fn generate_money_for_wallet(client: &WalletClientWrapper, bitcoind_client: &BitcoinCoreClient) {
    // generate money to p2pkh addresses
    let addr = client.new_address(AddressType::P2PKH);
    let change_addr = client.new_change_address(AddressType::P2PKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    // generate money to p2shwh addresses
    let addr = client.new_address(AddressType::P2SHWH);
    let change_addr = client.new_change_address(AddressType::P2SHWH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    // generate money to p2wkh addresses
    let addr = client.new_address(AddressType::P2WKH);
    let change_addr = client.new_change_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 600_000_000);
}

#[test]
fn sanity_check() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server and initialize wallet client
    let client = launch_server_and_wait(tmp_db_path(), cfg);

    // generate wallet address and send money to it
    // sync with blockchain
    // check wallet balance
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 100_000_000);

    shutdown_and_wait(&client);
}

#[test]
fn base_wallet_functionality() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait(tmp_db_path(), cfg);
    generate_money_for_wallet(&client, &bitcoind_client);

    // select all available utxos
    // generate destination address
    // check that generated transaction valid and can be send to blockchain
    let ops: Vec<RpcOutPoint> = client.get_utxo_list()
        .iter_mut()
        .map(|utxo| utxo.take_out_point())
        .collect();
    let dest_addr = client.new_address(AddressType::P2WKH);
    let encoded_tx = client.make_tx(ops, dest_addr, 150_000_000, true);
    let tx: Transaction = deserialize(&encoded_tx).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();

    shutdown_and_wait(&client);
}

#[test]
fn base_persistent_storage() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server and initialize wallet client
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    // generate wallet address and send money to it
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 100_000_000);

    // shutdown wallet and recover wallet's state from persistent storage
    restart_wallet(&client, db_path, cfg);

    // balance should not change after restart
    assert_eq!(client.wallet_balance(), 100_000_000);

    // wallet should remain viable after restart, so try to make some ordinary actions
    // and check wallet's state
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 200_000_000);

    shutdown_and_wait(&client);
}

#[test]
fn extended_persistent_storage() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());
    generate_money_for_wallet(&client, &bitcoind_client);

    // shutdown wallet and recover wallet's state from persistent storage
    restart_wallet(&client, db_path.clone(), cfg.clone());

    // select all available utxos
    // generate destination address
    // spend selected utxos
    let dest_addr = client.new_address(AddressType::P2WKH);
    let ops: Vec<RpcOutPoint> = client.get_utxo_list()
        .iter_mut()
        .map(|utxo| utxo.take_out_point())
        .collect();
    let encoded_tx = client.make_tx(ops, dest_addr, 150_000_000, true);
    let tx: Transaction = deserialize(&encoded_tx).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    // shutdown wallet and recover wallet's state from persistent storage
    restart_wallet(&client, db_path, cfg);

    // balance should not change after restart
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    shutdown_and_wait(&client);
}

#[test]
fn make_tx_call() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());
    generate_money_for_wallet(&client, &bitcoind_client);

    // select utxo subset
    // generate destination address
    // spend selected utxo subset
    let ops = client.get_utxo_list()
        .iter_mut()
        .take(2)
        .map(|utxo| utxo.take_out_point())
        .collect();
    let dest_addr = client.new_address(AddressType::P2WKH);
    client.make_tx(ops, dest_addr, 150_000_000, true);
    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = client.get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);

    shutdown_and_wait(&client);
}

#[test]
fn send_coins_call() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());
    generate_money_for_wallet(&client, &bitcoind_client);

    // generate destination address
    // send coins to itself
    // sync with blockchain
    let dest_addr = client.new_address(AddressType::P2WKH);
    client.send_coins(dest_addr, 150_000_000, true, false).unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    client.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = client.get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);

    shutdown_and_wait(&client);
}

#[test]
fn lock_coins_flag_success() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait(tmp_db_path(), cfg.clone());
    generate_money_for_wallet(&client, &bitcoind_client);

    // generate destination address
    // lock all utxos
    // unlock some of them
    // try to lock again
    // should work without errors
    let dest_addr = client.new_address(AddressType::P2WKH);
    client.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        false,
        true,
    ).unwrap();
    client.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        false,
        true,
    ).unwrap();
    let (_, lock_id) = client.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        false,
        true,
    ).unwrap();
    client.unlock_coins(lock_id);

    client.send_coins(
        dest_addr,
        200_000_000 - 10_000,
        true,
        true,
    ).unwrap();

    shutdown_and_wait(&client);
}

#[test]
fn lock_coins_flag_fail() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait(tmp_db_path(), cfg.clone());
    generate_money_for_wallet(&client, &bitcoind_client);

    // generate destination address
    // lock all utxos
    // try to lock again
    // should finish with error
    let dest_addr = client.new_address(AddressType::P2WKH);
    client.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        false,
        true,
    ).unwrap();
    client.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        false,
        true,
    ).unwrap();
    client.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        false,
        true,
    ).unwrap();

    // should panic, no available coins left
    let result = client.send_coins(
        dest_addr,
        200_000_000 - 10_000,
        true,
        false,
    );
    assert!(result.is_err());

    shutdown_and_wait(&client);
}

// TODO(evg): tests for lock persistence
// TODO(evg): tests for witness_only flag