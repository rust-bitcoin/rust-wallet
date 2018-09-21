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
    let p2pkh_account = ac.account(0, AccountAddressType::P2PKH).unwrap();
    let addr = p2pkh_account.borrow_mut().new_address().unwrap();
    let change_addr = p2pkh_account.borrow_mut().new_change_address().unwrap();
    println!("P2PKH        address: {}", addr);
    println!("P2PKH change address: {}\n", change_addr);

    let p2shwh_account = ac.account(0, AccountAddressType::P2SHWH).unwrap();
    let addr = p2shwh_account.borrow_mut().new_address().unwrap();
    let change_addr = p2shwh_account.borrow_mut().new_change_address().unwrap();
    println!("P2SHWH        address: {}", addr);
    println!("P2SHWH change address: {}\n", change_addr);

    let p2wkh_account = ac.account(0, AccountAddressType::P2WKH).unwrap();
    let addr = p2wkh_account.borrow_mut().new_address().unwrap();
    let change_addr = p2wkh_account.borrow_mut().new_change_address().unwrap();
    println!("P2WKH        address: {}", addr);
    println!("P2WKH change address: {}\n", change_addr);

    let p2wkh_addr = p2wkh_account.borrow_mut().new_address().unwrap();
    println!("final addr: {:?}\n\n", p2wkh_addr);

    ac.sync_with_blockchain();
    println!("{:?}\n", p2pkh_account.borrow_mut().get_utxo_list());
    println!("{:?}\n", p2shwh_account.borrow_mut().get_utxo_list());
    println!("{:?}\n\n", p2wkh_account.borrow_mut().get_utxo_list());

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