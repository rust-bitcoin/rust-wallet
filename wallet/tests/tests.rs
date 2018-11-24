extern crate tc_coblox_bitcoincore;
extern crate testcontainers;
extern crate bitcoin_rpc_client;
extern crate bitcoin;
extern crate hex;
extern crate wallet;
extern crate rand;
extern crate log;
extern crate simple_logger;
extern crate bitcoin_core_io;

use tc_coblox_bitcoincore::BitcoinCore;
use testcontainers::{
    clients::DockerCli,
    Docker, Container,
};
use bitcoin_rpc_client::{BitcoinCoreClient, BitcoinRpcApi, Address};
use rand::{Rng, thread_rng};
use bitcoin_core_io::BitcoinCoreIO;

use std::str::FromStr;

use wallet::{
    account::AccountAddressType,
    accountfactory::{AccountFactory, WalletConfig, BitcoindConfig},
    interface::Wallet,
};

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

fn tmp_db_path() -> String {
    let mut rez: String = "/tmp/test_".to_string();
    let suffix: String = thread_rng().gen_ascii_chars().take(10).collect();
    rez.push_str(&suffix);
    rez
}

fn generate_money_for_wallet(af: &mut AccountFactory, bitcoind_client: &BitcoinCoreClient) {
    // generate money to p2pkh addresses
    let addr = af.new_address(AccountAddressType::P2PKH).unwrap();
    let change_addr = af.new_change_address(AccountAddressType::P2PKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    // generate money to p2shwh addresses
    let addr = af.new_address(AccountAddressType::P2SHWH).unwrap();
    let change_addr = af.new_change_address(AccountAddressType::P2SHWH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    // generate money to p2wkh addresses
    let addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    let change_addr = af.new_change_address(AccountAddressType::P2WKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();
    assert_eq!(af.wallet_balance(), 600_000_000);
}

#[test]
fn sanity_check() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();

    // generate wallet address and send money to it
    // sync with blockchain
    // check wallet balance
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&dest_addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();
    assert_eq!(af.wallet_balance(), 100_000_000);
}

#[test]
fn base_wallet_functionality() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();
    generate_money_for_wallet(&mut af, &bitcoind_client);

    // select all available utxos
    // generate destination address
    // check that generated transaction valid and can be send to blockchain
    let ops = af.get_utxo_list()
        .iter()
        .map(|utxo| utxo.out_point)
        .collect();
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    let tx = af.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
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

    {
        // initialize wallet with blockchain source
        // additional scope destroys wallet object(aka wallet restart)
        let bio = Box::new(BitcoinCoreIO::new(
            BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let mut af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

        // generate wallet address and send money to it
        let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
        bitcoind_client.send_to_address(&Address::from_str(&dest_addr).unwrap(), 1.0).unwrap().unwrap();
        bitcoind_client.generate(1).unwrap().unwrap();
        af.sync_with_tip();
        assert_eq!(af.wallet_balance(), 100_000_000);
    }

    // recover wallet's state from persistent storage
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path), bio).unwrap();

    // balance should not change after restart
    assert_eq!(af.wallet_balance(), 100_000_000);

    // wallet should remain viable after restart, so try to make some ordinary actions
    // and check wallet's state
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&dest_addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();
    assert_eq!(af.wallet_balance(), 200_000_000);
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

    {
        // initialize wallet with blockchain source and generated money
        // additional scope destroys wallet object(aka wallet restart)
        let bio = Box::new(BitcoinCoreIO::new(
            BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let mut af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();
        generate_money_for_wallet(&mut af, &bitcoind_client);
    }

    {
        // recover wallet's state from persistent storage
        // additional scope destroys wallet object(aka wallet restart)
        let bio = Box::new(BitcoinCoreIO::new(
            BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let mut af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

        // select all available utxos
        // generate destination address
        // spend selected utxos
        let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
        let ops = af.get_utxo_list()
            .iter()
            .map(|utxo| utxo.out_point)
            .collect();
        let tx = af.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
        bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
        bitcoind_client.generate(1).unwrap().unwrap();
        af.sync_with_tip();

        // wallet send money to itself, so balance decreased only by fee
        assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);
    }

    // recover wallet's state from persistent storage
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

    // balance should not change after restart
    assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);
}

#[test]
fn make_tx_call() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();
    generate_money_for_wallet(&mut af, &bitcoind_client);

    // select utxo subset
    // generate destination address
    // spend selected utxo subset
    let ops = af.get_utxo_list()
        .iter()
        .take(2)
        .map(|utxo| utxo.out_point)
        .collect();
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    let tx = af.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = af.get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);
}

#[test]
fn send_coins_call() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();
    generate_money_for_wallet(&mut af, &bitcoind_client);

    // generate destination address
    // send coins to itself
    // sync with blockchain
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    let (tx, _) = af.send_coins(
        dest_addr,
        150_000_000,
        false,
        false,
        true,
    ).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = af.get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);
}

#[test]
fn lock_coins_flag_success() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();
    generate_money_for_wallet(&mut af, &bitcoind_client);

    // generate destination address
    // lock all utxos
    // unlock some of them
    // try to lock again
    // should work without errors
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    af.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    af.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    let (_, lock_id) = af.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    af.unlock_coins(lock_id);

    let (tx, _) = af.send_coins(
        dest_addr,
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    af.publish_tx(&tx);
}

#[test]
fn lock_coins_flag_fail() {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let bio = Box::new(BitcoinCoreIO::new(
        BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();
    generate_money_for_wallet(&mut af, &bitcoind_client);

    // generate destination address
    // lock all utxos
    // try to lock again
    // should finish with error
    let dest_addr = af.new_address(AccountAddressType::P2WKH).unwrap();
    af.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    af.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    af.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();

    // should finish with error, no available coins left
    let result = af.send_coins(
        dest_addr,
        200_000_000 - 10_000,
        false,
        false,
        true,
    );
    assert!(result.is_err());
}

// TODO(evg): tests for lock persistence
// TODO(evg): tests for witness_only flag