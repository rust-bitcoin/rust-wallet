extern crate bitcoin;
extern crate wallet;
extern crate hex;

use bitcoin::network::constants::Network;
use bitcoin::network::encodable::ConsensusEncodable;
use bitcoin::network::serialize::RawEncoder;

use wallet::accountfactory::{AccountFactory, BitcoindConfig};
use wallet::keyfactory::MasterKeyEntropy;
use wallet::account::AccountAddressType;

fn main() {
    let cfg = BitcoindConfig::new(
        "http://127.0.0.1:18332".to_owned(),
        "user".to_owned(),
        "password".to_owned(),
    );

    let mut ac = AccountFactory::new_no_random(MasterKeyEntropy::Recommended,
                                           Network::Regtest, "", "easy", cfg).unwrap();
    ac.initialize();
    {
        let guarded = ac.get_account(AccountAddressType::P2PKH);
        let mut p2pkh_account = guarded.write().unwrap();
        let addr = p2pkh_account.new_address().unwrap();
        let change_addr = p2pkh_account.new_change_address().unwrap();
        println!("P2PKH        address: {}", addr);
        println!("P2PKH change address: {}\n", change_addr);
    }

    {
        let guarded = ac.get_account(AccountAddressType::P2SHWH);
        let mut p2shwh_account = guarded.write().unwrap();
        let addr = p2shwh_account.new_address().unwrap();
        let change_addr = p2shwh_account.new_change_address().unwrap();
        println!("P2SHWH        address: {}", addr);
        println!("P2SHWH change address: {}\n", change_addr);
    }

    let p2wkh_addr = {
        let guarded = ac.get_account(AccountAddressType::P2WKH);
        let mut p2wkh_account = guarded.write().unwrap();
        let addr = p2wkh_account.new_address().unwrap();
        let change_addr = p2wkh_account.new_change_address().unwrap();
        println!("P2WKH        address: {}", addr);
        println!("P2WKH change address: {}\n", change_addr);

        let p2wkh_addr = p2wkh_account.new_address().unwrap();
        println!("final addr: {:?}\n\n", p2wkh_addr);
        p2wkh_addr
    };

    ac.sync_with_blockchain();
    {
        let guarded = ac.get_account(AccountAddressType::P2PKH);
        let p2pkh_account  = guarded.read().unwrap();

        let guarded = ac.get_account(AccountAddressType::P2SHWH);
        let p2shwh_account = guarded.read().unwrap();

        let guarded = ac.get_account(AccountAddressType::P2WKH);
        let p2wkh_account  = guarded.read().unwrap();

        println!("{:?}\n", p2pkh_account.get_utxo_list());
        println!("{:?}\n", p2shwh_account.get_utxo_list());
        println!("{:?}\n\n", p2wkh_account.get_utxo_list());
    }

    let utxo_list = ac.get_utxo_list();
    let mut ops = Vec::new();
    for utxo in &utxo_list {
        ops.push(utxo.out_point);
    }

    let tx = ac.make_tx(ops, p2wkh_addr);
    // println!("{:?}", tx);

    let writer: Vec<u8> = Vec::new();
    let mut encoder = RawEncoder::new(writer);
    tx.consensus_encode(&mut encoder).unwrap();
    println!("{:?}", hex::encode(encoder.into_inner()));
}