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
    let client = BitcoinCoreClient::new(url.as_str(), auth.username(), auth.password());
    let cfg = BitcoindConfig::new(url, auth.username().to_owned(), auth.password().to_owned(),
                                  format!("tcp://localhost:{}", zmq_port), format!("tcp://localhost:{}", zmq_port));

    (client, cfg)
}

fn tmp_db_path() -> String {
    let mut rez: String = "/tmp/test_".to_string();
    let suffix: String = thread_rng().gen_ascii_chars().take(10).collect();
    rez.push_str(&suffix);
    rez
}

fn generate_money_for_wallet(af: &mut AccountFactory, bitcoind_client: &BitcoinCoreClient) {
    let addr = af.get_account_mut(AccountAddressType::P2PKH).new_address().unwrap();
    let change_addr = af.get_account_mut(AccountAddressType::P2PKH).new_change_address().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    let addr = af.get_account_mut(AccountAddressType::P2SHWH).new_address().unwrap();
    let change_addr = af.get_account_mut(AccountAddressType::P2SHWH).new_change_address().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    let addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    let change_addr = af.get_account_mut(AccountAddressType::P2WKH).new_change_address().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();
    assert_eq!(af.wallet_balance(), 600_000_000);
}

#[test]
fn test_base_wallet_functionality() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (client, cfg) = bitcoind_init(&node);
    client.generate(110).unwrap().unwrap();

    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut ac = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();
    generate_money_for_wallet(&mut ac, &client);

    client.generate(1).unwrap().unwrap();
    ac.sync_with_tip();

    // select all available utxos
    let utxo_list = ac.get_utxo_list();
    let mut ops = Vec::new();
    for utxo in &utxo_list {
        ops.push(utxo.out_point);
    }

    let p2wkh_addr = ac.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    // check that generated transaction valid and can be send to blockchain
    ac.make_tx(ops, p2wkh_addr, 150_000_000, true).unwrap();

    // client.get_raw_transaction_serialized(&txid).unwrap().unwrap();
}

#[test]
fn test_base_client_server_functionality() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(tmp_db_path()), bio).unwrap();

    let addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();
    assert_eq!(af.wallet_balance(), 100_000_000);
}

#[test]
fn test_base_persistent_storage() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    {
        let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let mut af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

        let addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
        bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
        bitcoind_client.generate(1).unwrap().unwrap();
        af.sync_with_tip();
        assert_eq!(af.wallet_balance(), 100_000_000);
    }

    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path), bio).unwrap();

    // balance should not change after restart
    assert_eq!(af.wallet_balance(), 100_000_000);

    // wallet should remain viable after restart
    let addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();
    assert_eq!(af.wallet_balance(), 200_000_000);
}

#[test]
fn test_base_wallet_functionality_cs_api() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    {
        let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let mut af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

        generate_money_for_wallet(&mut af, &bitcoind_client);
    }

    {
        let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let mut af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

        let dest_addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
        let utxo_list = af.get_utxo_list();
        let mut ops = Vec::new();
        for utxo in &utxo_list {
            ops.push(utxo.out_point);
        }
        af.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
        // TODO(evg): remove it?
        // bitcoind_client.get_raw_transaction_serialized(&txid).unwrap().unwrap();
        bitcoind_client.generate(1).unwrap().unwrap();
        af.sync_with_tip();

        // wallet send money to itself, so balance decreased only by fee
        assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);
    }

    {
        let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
        let af = AccountFactory::new_no_random(
            WalletConfig::with_db_path(db_path.clone()), bio).unwrap();
        // balance should not change after restart
        assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);
    }
}

#[test]
fn test_make_tx_call() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

    generate_money_for_wallet(&mut af, &bitcoind_client);

    // select utxo subset
    let utxo_list = af.get_utxo_list();
    let mut ops = Vec::new();
    ops.push(utxo_list[0].out_point.clone());
    ops.push(utxo_list[1].out_point.clone());

    let dest_addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    af.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
    // TODO(evg): get tx assert
    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();

    assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);

    let utxo_list = af.get_utxo_list();
    let mut ok = false;
    for utxo in &utxo_list {
        if utxo.value == 200_000_000 - 150_000_000 - 10_000 {
            ok = true;
        }
    }
    assert!(ok);
}

#[test]
fn test_send_coins_call() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

    generate_money_for_wallet(&mut af, &bitcoind_client);

    let dest_addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    af.send_coins(dest_addr, 150_000_000, false, false, true).unwrap();
    // TODO(evg): add get assertions

    bitcoind_client.generate(1).unwrap().unwrap();
    af.sync_with_tip();


    assert_eq!(af.wallet_balance(), 600_000_000 - 10_000);

    let utxo_list = af.get_utxo_list();
    let mut ok = false;
    for utxo in &utxo_list {
        if utxo.value == 200_000_000 - 150_000_000 - 10_000 {
            ok = true;
        }
    }
    assert!(ok);
}

#[test]
fn test_lock_coins_flag_success() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path.clone()), bio).unwrap();

    generate_money_for_wallet(&mut af, &bitcoind_client);

    let dest_addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    af.send_coins(dest_addr.clone(), 200_000_000 - 10_000, true, false, false).unwrap();
    af.send_coins(dest_addr.clone(), 200_000_000 - 10_000, true, false, false).unwrap();
    let (_, lock_id) = af.send_coins(dest_addr.clone(), 200_000_000 - 10_000, true, false, false).unwrap();
    af.unlock_coins(lock_id);

    let (tx, _) = af.send_coins(dest_addr, 200_000_000 - 10_000, true, false, false).unwrap();
    af.publish_tx(&tx);
}

#[test]
fn test_lock_coins_flag() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg) = bitcoind_init(&node);
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();
    let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
    let mut af = AccountFactory::new_no_random(
        WalletConfig::with_db_path(db_path.clone()), bio).unwrap();


    generate_money_for_wallet(&mut af, &bitcoind_client);

    let dest_addr = af.get_account_mut(AccountAddressType::P2WKH).new_address().unwrap();
    af.send_coins(dest_addr.clone(), 200_000_000 - 10_000, true, false, false).unwrap();
    af.send_coins(dest_addr.clone(), 200_000_000 - 10_000, true, false, false).unwrap();
    af.send_coins(dest_addr.clone(), 200_000_000 - 10_000, true, false, false).unwrap();

    // should panic, no available coins left
    let rez = af.send_coins(dest_addr, 200_000_000 - 10_000, false, false, true);
    assert!(rez.is_err());
}

// TODO(evg): tests for lock persistence
// TODO(evg): tests for witness_only flag

// TODO(evg): tests for zmq ntfn