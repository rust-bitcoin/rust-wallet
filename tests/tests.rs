extern crate bitcoin_rpc_client;
extern crate tc_coblox_bitcoincore;
extern crate testcontainers;
extern crate bitcoin;
extern crate wallet;
extern crate hex;

use bitcoin_rpc_client::BitcoinCoreClient;
use bitcoin_rpc_client::BitcoinRpcApi;
use tc_coblox_bitcoincore::BitcoinCore;
use testcontainers::clients::DockerCli;
use testcontainers::Docker;

use bitcoin::network::constants::Network;
use bitcoin::network::encodable::ConsensusEncodable;
use bitcoin::network::serialize::RawEncoder;
use wallet::accountfactory::{AccountFactory, BitcoindConfig};
use wallet::keyfactory::MasterKeyEntropy;
use wallet::account::AccountAddressType;
use bitcoin_rpc_client::{Address, SerializedRawTransaction};

use std::str::FromStr;

#[test]
fn test_base_wallet_functionality() {
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());

    let (client, cfg) = {
        let host_port = node.get_host_port(18443).unwrap();
        let url = format!("http://localhost:{}", host_port);
        let auth = node.image().auth();
        let client = BitcoinCoreClient::new(url.as_str(), auth.username(), auth.password());
        let cfg = BitcoindConfig::new(url, auth.username().to_owned(), auth.password().to_owned());

        (client, cfg)
    };

    client.generate(110).unwrap().unwrap();

    let mut ac = AccountFactory::new_no_random(MasterKeyEntropy::Recommended,
                                               Network::Regtest, "", "easy", cfg).unwrap();
    ac.initialize();
    {
        let guarded = ac.get_account(AccountAddressType::P2PKH);
        let mut p2pkh_account = guarded.write().unwrap();
        let addr = p2pkh_account.new_address().unwrap();
        let change_addr = p2pkh_account.new_change_address().unwrap();
        client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0);
        client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0);
    }

    {
        let guarded = ac.get_account(AccountAddressType::P2SHWH);
        let mut p2shwh_account = guarded.write().unwrap();
        let addr = p2shwh_account.new_address().unwrap();
        let change_addr = p2shwh_account.new_change_address().unwrap();
        client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
        client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0);
    }

    let p2wkh_addr = {
        let guarded = ac.get_account(AccountAddressType::P2WKH);
        let mut p2wkh_account = guarded.write().unwrap();
        let addr = p2wkh_account.new_address().unwrap();
        let change_addr = p2wkh_account.new_change_address().unwrap();
        client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0);
        client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0);

        p2wkh_account.new_address().unwrap()
    };

    client.generate(1).unwrap().unwrap();

    ac.sync_with_blockchain();

    let utxo_list = ac.get_utxo_list();
    let mut ops = Vec::new();
    for utxo in &utxo_list {
        ops.push(utxo.out_point);
    }

    let tx = ac.make_tx(ops, p2wkh_addr);

    let writer: Vec<u8> = Vec::new();
    let mut encoder = RawEncoder::new(writer);
    tx.consensus_encode(&mut encoder).unwrap();

    let txid = client.send_raw_transaction(SerializedRawTransaction::from(tx)).unwrap().unwrap();
    client.get_raw_transaction_serialized(&txid).unwrap().unwrap();
}