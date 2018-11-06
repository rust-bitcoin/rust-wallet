extern crate tc_coblox_bitcoincore;
extern crate testcontainers;
extern crate bitcoin_rpc_client;
extern crate bitcoin;
extern crate hex;
extern crate wallet;
extern crate grpc;
extern crate rand;
extern crate log;
extern crate simple_logger;

use tc_coblox_bitcoincore::BitcoinCore;
use testcontainers::{
    clients::DockerCli,
    Docker, Container,
};
use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, Address, SerializedRawTransaction};
use bitcoin::network::{
    encodable::ConsensusEncodable,
    serialize::RawEncoder,
};
use rand::{Rng, thread_rng};

use std::{
    str::FromStr,
    thread,
    time::Duration,
};

use wallet::{
    account::AccountAddressType,
    accountfactory::{AccountFactory, WalletConfig, BitcoindConfig},
    server::{launch_server, WalletClientWrapper, DEFAULT_WALLET_RPC_PORT},
    walletrpc::AddressType,
};

const LAUNCH_SERVER_DELAY_MS: u64 = 3000;
const SHUTDOWN_SERVER_DELAY_MS: u64 = 2000;
const ZMQ_BLOCK_NTFN_DELAY_MS: u64 = 1000;

fn bitcoind_init(node: &Container<DockerCli, BitcoinCore>) -> (BitcoinCoreClient, BitcoindConfig) {
    let host_port = node.get_host_port(18443).unwrap();
    let zmq_port = node.get_host_port(18501).unwrap();
    let url = format!("http://localhost:{}", host_port);
    let auth = node.image().auth();
    let client = BitcoinCoreClient::new(url.as_str(), auth.username(), auth.password());
    let cfg = BitcoindConfig::new(url, auth.username().to_owned(), auth.password().to_owned(),
                                  format!("tcp://localhost:{}", zmq_port), format!("tcp://localhost:{}", zmq_port));

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

fn generate_and_wait(client: &BitcoinCoreClient, number_of_blocks: u32) {
    client.generate(number_of_blocks).unwrap().unwrap();
    // wait until zmq inform us about newly generated block
    thread::sleep(Duration::from_millis(ZMQ_BLOCK_NTFN_DELAY_MS));
}

fn tmp_db_path() -> String {
    let mut rez: String = "/tmp/test_".to_string();
    let suffix: String = thread_rng().gen_ascii_chars().take(10).collect();
    rez.push_str(&suffix);
    rez
}

#[test]
fn test_base_wallet_functionality() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (client, cfg) = bitcoind_init(&node);
    client.generate(110).unwrap().unwrap();

    let mut ac = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), cfg).unwrap();
    {
        // let guarded = ac.get_account(AccountAddressType::P2PKH);
        // let mut p2pkh_account = guarded.write().unwrap();
        let p2pkh_account = ac.get_account_mut(AccountAddressType::P2PKH);
        let addr = p2pkh_account.new_address().unwrap();
        let change_addr = p2pkh_account.new_change_address().unwrap();
        client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
        client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();
    }

    {
        // let guarded = ac.get_account(AccountAddressType::P2SHWH);
        // let mut p2shwh_account = guarded.write().unwrap();
        let p2shwh_account = ac.get_account_mut(AccountAddressType::P2SHWH);
        let addr = p2shwh_account.new_address().unwrap();
        let change_addr = p2shwh_account.new_change_address().unwrap();
        client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
        client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();
    }

    let p2wkh_addr = {
        // let guarded = ac.get_account(AccountAddressType::P2WKH);
        // let mut p2wkh_account = guarded.write().unwrap();
        let mut p2wkh_account = ac.get_account_mut(AccountAddressType::P2WKH);
        let addr = p2wkh_account.new_address().unwrap();
        let change_addr = p2wkh_account.new_change_address().unwrap();
        client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
        client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

        p2wkh_account.new_address().unwrap()
    };

    client.generate(1).unwrap().unwrap();
    ac.sync_with_blockchain();

    // select all available utxos
    let utxo_list = ac.get_utxo_list();
    let mut ops = Vec::new();
    for utxo in &utxo_list {
        ops.push(utxo.out_point);
    }

    let tx = ac.make_tx(ops, p2wkh_addr, 150_000_000).unwrap();

    // check that generated transaction valid and can be send to blockchain
    let writer: Vec<u8> = Vec::new();
    let mut encoder = RawEncoder::new(writer);
    tx.consensus_encode(&mut encoder).unwrap();

    let txid = client.send_raw_transaction(SerializedRawTransaction::from(tx)).unwrap().unwrap();
    client.get_raw_transaction_serialized(&txid).unwrap().unwrap();
}

#[test]
fn test_base_client_server_functionality() {
    simple_logger::init_with_level(log::Level::Info).unwrap();

    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let client = launch_server_and_wait(tmp_db_path(), cfg);

    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    generate_and_wait(&bitcoind_client, 1);
    assert_eq!(client.wallet_balance(), 100_000_000);

    shutdown_and_wait(&client);
}

#[test]
fn test_base_persistent_storage() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    generate_and_wait(&bitcoind_client, 1);
    assert_eq!(client.wallet_balance(), 100_000_000);

    restart_wallet(&client, db_path, cfg);

    // balance should not change after restart
    assert_eq!(client.wallet_balance(), 100_000_000);

    // wallet should remain viable after restart
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    generate_and_wait(&bitcoind_client, 1);
    assert_eq!(client.wallet_balance(), 200_000_000);

    shutdown_and_wait(&client);
}

fn generate_money_for_wallet(client: &WalletClientWrapper, bitcoind_client: &BitcoinCoreClient) {
    let addr = client.new_address(AddressType::P2PKH);
    let change_addr = client.new_change_address(AddressType::P2PKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    let addr = client.new_address(AddressType::P2SHWH);
    let change_addr = client.new_change_address(AddressType::P2SHWH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    let addr = client.new_address(AddressType::P2WKH);
    let change_addr = client.new_change_address(AddressType::P2WKH);
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    generate_and_wait(&bitcoind_client, 1);
    assert_eq!(client.wallet_balance(), 600_000_000);
}

#[test]
fn test_base_wallet_functionality_cs_api() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    generate_money_for_wallet(&client, &bitcoind_client);

    restart_wallet(&client, db_path.clone(), cfg.clone());

    let dest_addr = client.new_address(AddressType::P2WKH);
    let tx: &str = &hex::encode(client.make_tx(true, Vec::new(), dest_addr, 150_000_000, false));
    let txid = bitcoind_client.send_raw_transaction(SerializedRawTransaction::from(tx)).unwrap().unwrap();
    bitcoind_client.get_raw_transaction_serialized(&txid).unwrap().unwrap();
    generate_and_wait(&bitcoind_client, 1);

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    restart_wallet(&client, db_path, cfg);

    // balance should not change after restart
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    shutdown_and_wait(&client);
}

#[test]
fn test_make_tx_call() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    generate_money_for_wallet(&client, &bitcoind_client);

    // select utxo subset
    let utxo_list = client.get_utxo_list();
    let mut ops = Vec::new();
    ops.push(utxo_list[0].out_point.clone().unwrap());
    ops.push(utxo_list[1].out_point.clone().unwrap());

    let dest_addr = client.new_address(AddressType::P2WKH);
    client.make_tx(false, ops, dest_addr, 150_000_000, true);
    generate_and_wait(&bitcoind_client, 1);

    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    let utxo_list = client.get_utxo_list();
    let mut ok = false;
    for utxo in &utxo_list {
        if utxo.value == 200_000_000 - 150_000_000 - 10_000 {
            ok = true;
        }
    }
    assert!(ok);

    shutdown_and_wait(&client);
}

#[test]
fn test_send_coins_call() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    generate_money_for_wallet(&client, &bitcoind_client);

    let dest_addr = client.new_address(AddressType::P2WKH);
    client.send_coins(dest_addr, 150_000_000, true, false).unwrap();
    generate_and_wait(&bitcoind_client, 1);

    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    let utxo_list = client.get_utxo_list();
    let mut ok = false;
    for utxo in &utxo_list {
        if utxo.value == 200_000_000 - 150_000_000 - 10_000 {
            ok = true;
        }
    }
    assert!(ok);

    shutdown_and_wait(&client);
}

#[test]
fn test_lock_coins_flag_success() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    generate_money_for_wallet(&client, &bitcoind_client);

    let dest_addr = client.new_address(AddressType::P2WKH);
    client.send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true).unwrap();
    let (_, lock_id) = client.send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true).unwrap();
    client.unlock_coins(lock_id);

    client.send_coins(dest_addr, 200_000_000 - 10_000, true, true).unwrap();
    shutdown_and_wait(&client);
}

#[test]
// #[ignore]
// #[should_panic]
fn test_lock_coins_flag() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let client = launch_server_and_wait(db_path.clone(), cfg.clone());

    generate_money_for_wallet(&client, &bitcoind_client);

    let dest_addr = client.new_address(AddressType::P2WKH);
    client.send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true).unwrap();
    client.send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true).unwrap();
    client.send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true).unwrap();

    // should panic, no available coins left
    let rez = client.send_coins(dest_addr, 200_000_000 - 10_000, true, false);
    assert!(rez.is_err());
    shutdown_and_wait(&client);
}

// TODO(evg): tests for lock persistence
// TODO(evg): tests for witness_only flag

// TODO(evg): tests for zmq ntfn