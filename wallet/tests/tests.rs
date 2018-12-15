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

use std::{
    thread,
    time::Duration,
    str::FromStr,
    process::{Command, Child},
};

use wallet::{
    account::AccountAddressType,
    walletlibrary::{WalletConfig, BitcoindConfig},
    electrumx::ElectrumxWallet,
    default::WalletWithTrustedFullNode,
    interface::{WalletLibraryInterface, Wallet},
};

const ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS: u64 = 5000;
const LAUNCH_ELECTRUMX_SERVER_DELAY_MS: u64 = 500;

fn bitcoind_init(node: &Container<DockerCli, BitcoinCore>) -> (BitcoinCoreClient, BitcoindConfig, u32) {
    let host_port = node.get_host_port(18443).unwrap();
    let zmq_port = node.get_host_port(18501).unwrap();
    let url = format!("http://localhost:{}", host_port);
    let auth = node.image().auth();
    let bitcoind_client = BitcoinCoreClient::new(
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

    (bitcoind_client, cfg, host_port)
}

fn tmp_db_path() -> String {
    let mut rez: String = "/tmp/test_".to_string();
    let suffix: String = thread_rng().gen_ascii_chars().take(10).collect();
    rez.push_str(&suffix);
    rez
}

#[derive(PartialEq, Clone)]
enum BlockChainProvider {
    TrustedFullNode,
    Electrumx,
}

fn generate_money_for_wallet(af: &mut Box<Wallet>, bitcoind_client: &BitcoinCoreClient, provider: BlockChainProvider) {
    // generate money to p2pkh addresses
    let addr = af.wallet_lib_mut().new_address(AccountAddressType::P2PKH).unwrap();
    let change_addr = af.wallet_lib_mut().new_change_address(AccountAddressType::P2PKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    // generate money to p2shwh addresses
    let addr = af.wallet_lib_mut().new_address(AccountAddressType::P2SHWH).unwrap();
    let change_addr = af.wallet_lib_mut().new_change_address(AccountAddressType::P2SHWH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    // generate money to p2wkh addresses
    let addr = af.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    let change_addr = af.wallet_lib_mut().new_change_address(AccountAddressType::P2WKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0).unwrap().unwrap();

    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));
    }
    af.sync_with_tip();
    assert_eq!(af.wallet_lib().wallet_balance(), 600_000_000);
}

macro_rules! test {
    ($base:ident) => {
        mod $base {
            use super::{BlockChainProvider, $base};
            #[test]
            fn trusted_full_node() {
                $base(BlockChainProvider::TrustedFullNode);
            }
            #[test]
            fn electrumx() {
                $base(BlockChainProvider::Electrumx);
            }
        }
    };
}

test!(sanity_check);
test!(base_wallet_functionality);
test!(base_persistent_storage);
test!(extended_persistent_storage);
test!(make_tx_call);
test!(send_coins_call);
test!(lock_coins_flag_success);
test!(lock_coins_flag_fail);

fn sanity_check(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let electrs_process = match provider {
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        },
        BlockChainProvider::TrustedFullNode => None
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(tmp_db_path()), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(tmp_db_path())).unwrap());
            electrumx_wallet
        }
    };

    // generate wallet address and send money to it
    // sync with blockchain
    // check wallet balance
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&dest_addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));
    }
    wallet.sync_with_tip();
    assert_eq!(wallet.wallet_lib().wallet_balance(), 100_000_000);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn base_wallet_functionality(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let electrs_process = match provider {
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        },
        BlockChainProvider::TrustedFullNode => None
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(tmp_db_path()), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(tmp_db_path())).unwrap());
            electrumx_wallet
        }
    };
    generate_money_for_wallet(&mut wallet, &bitcoind_client, provider.clone());

    // select all available utxos
    // generate destination address
    // check that generated transaction valid and can be send to blockchain
    let ops = wallet.wallet_lib().get_utxo_list()
        .iter()
        .map(|utxo| utxo.out_point)
        .collect();
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    let tx = wallet.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn base_persistent_storage(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let electrs_process = match provider {
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        },
        BlockChainProvider::TrustedFullNode => None
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    {
        // initialize wallet with blockchain source
        // additional scope destroys wallet object(aka wallet restart)
        let mut wallet = match provider {
            BlockChainProvider::TrustedFullNode => {
                let bio = Box::new(BitcoinCoreIO::new(
                    BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
                let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                    WalletConfig::with_db_path(db_path.clone()), bio).unwrap());
                default_wallet
            }
            BlockChainProvider::Electrumx => {
                let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                    WalletConfig::with_db_path(db_path.clone())).unwrap());
                electrumx_wallet
            }
        };

        // generate wallet address and send money to it
        let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
        bitcoind_client.send_to_address(&Address::from_str(&dest_addr).unwrap(), 1.0).unwrap().unwrap();
        bitcoind_client.generate(1).unwrap().unwrap();
        if provider == BlockChainProvider::Electrumx {
            thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));
        }
        wallet.sync_with_tip();
        assert_eq!(wallet.wallet_lib().wallet_balance(), 100_000_000);
    }

    // recover wallet's state from persistent storage
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(db_path), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(db_path)).unwrap());
            electrumx_wallet
        }
    };

    // balance should not change after restart
    assert_eq!(wallet.wallet_lib().wallet_balance(), 100_000_000);

    // wallet should remain viable after restart, so try to make some ordinary actions
    // and check wallet's state
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    bitcoind_client.send_to_address(&Address::from_str(&dest_addr).unwrap(), 1.0).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));
    }
    wallet.sync_with_tip();
    assert_eq!(wallet.wallet_lib().wallet_balance(), 200_000_000);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn extended_persistent_storage(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let mut electrs_process = match provider {
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        },
        BlockChainProvider::TrustedFullNode => None
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    {
        // initialize wallet with blockchain source and generated money
        // additional scope destroys wallet object(aka wallet restart)
        let mut wallet = match provider {
            BlockChainProvider::TrustedFullNode => {
                let bio = Box::new(BitcoinCoreIO::new(
                    BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
                let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                    WalletConfig::with_db_path(db_path.clone()), bio).unwrap());
                default_wallet
            }
            BlockChainProvider::Electrumx => {
                let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                    WalletConfig::with_db_path(db_path.clone())).unwrap());
                electrumx_wallet
            }
        };
        generate_money_for_wallet(&mut wallet, &bitcoind_client, provider.clone());
    }

    {
        // recover wallet's state from persistent storage
        // additional scope destroys wallet object(aka wallet restart)
        let mut wallet = match provider {
            BlockChainProvider::TrustedFullNode => {
                let bio = Box::new(BitcoinCoreIO::new(
                    BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
                let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                    WalletConfig::with_db_path(db_path.clone()), bio).unwrap());
                default_wallet
            }
            BlockChainProvider::Electrumx => {
                let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                    WalletConfig::with_db_path(db_path.clone())).unwrap());
                electrumx_wallet
            }
        };

        // select all available utxos
        // generate destination address
        // spend selected utxos
        let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
        let ops = wallet.wallet_lib().get_utxo_list()
            .iter()
            .map(|utxo| utxo.out_point)
            .collect();
        let tx = wallet.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
        bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
        bitcoind_client.generate(1).unwrap().unwrap();
        // It seems that electrumx server has some bugs so we should to restart it time-to-time
        // TODO(evg): find out and fix problem in electrumx server
        if provider == BlockChainProvider::Electrumx {
            thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));

            electrs_process.unwrap().kill().unwrap();
            electrs_process = Some(launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            ));
            thread::sleep(Duration::from_millis(LAUNCH_ELECTRUMX_SERVER_DELAY_MS));
            // reconnect after electrumx server restarting
            wallet.reconnect();
        }

        wallet.sync_with_tip();

        // wallet send money to itself, so balance decreased only by fee
        assert_eq!(wallet.wallet_lib().wallet_balance(), 600_000_000 - 10_000);
    }

    // recover wallet's state from persistent storage
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(db_path), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(db_path)).unwrap());
            electrumx_wallet
        }
    };

    // balance should not change after restart
    assert_eq!(wallet.wallet_lib().wallet_balance(), 600_000_000 - 10_000);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn make_tx_call(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let mut electrs_process = match provider {
        BlockChainProvider::TrustedFullNode => None,
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(tmp_db_path()), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(tmp_db_path())).unwrap());
            electrumx_wallet
        }
    };
    generate_money_for_wallet(&mut wallet, &bitcoind_client, provider.clone());

    // select utxo subset
    // generate destination address
    // spend selected utxo subset
    let ops = wallet.wallet_lib().get_utxo_list()
        .iter()
        .take(2)
        .map(|utxo| utxo.out_point)
        .collect();
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    let tx = wallet.make_tx(ops, dest_addr, 150_000_000, true).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    // It seems that electrumx server has some bugs so we should to restart it time-to-time
    // TODO(evg): find out and fix problem in electrumx server
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));

        electrs_process.unwrap().kill().unwrap();
        electrs_process = Some(launch_electrs_process(
            format!("{}:{}", cfg.user, cfg.password),
            format!("127.0.0.1:{}", host_port),
            "regtest".to_string(),
            tmp_db_path(),
        ));
        thread::sleep(Duration::from_millis(LAUNCH_ELECTRUMX_SERVER_DELAY_MS));
        // reconnect after electrumx server restarting
        wallet.reconnect();
    }

    wallet.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(wallet.wallet_lib().wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = wallet.wallet_lib().get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn send_coins_call(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let mut electrs_process = match provider {
        BlockChainProvider::TrustedFullNode => None,
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(tmp_db_path()), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(tmp_db_path())).unwrap());
            electrumx_wallet
        }
    };
    generate_money_for_wallet(&mut wallet, &bitcoind_client, BlockChainProvider::Electrumx);

    // generate destination address
    // send coins to itself
    // sync with blockchain
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    let (tx, _) = wallet.send_coins(
        dest_addr,
        150_000_000,
        false,
        false,
        true,
    ).unwrap();
    bitcoind_client.get_raw_transaction_serialized(&tx.txid()).unwrap().unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();

    // It seems that electrumx server has some bugs so we should to restart it time-to-time
    // TODO(evg): find out and fix problem in electrumx server
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS));

        electrs_process.unwrap().kill().unwrap();
        electrs_process = Some(launch_electrs_process(
            format!("{}:{}", cfg.user, cfg.password),
            format!("127.0.0.1:{}", host_port),
            "regtest".to_string(),
            tmp_db_path(),
        ));
        thread::sleep(Duration::from_millis(LAUNCH_ELECTRUMX_SERVER_DELAY_MS));
        // reconnect after electrumx server restarting
        wallet.reconnect();
    }

    wallet.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(wallet.wallet_lib().wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = wallet.wallet_lib().get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn lock_coins_flag_success(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let mut electrs_process = match provider {
        BlockChainProvider::TrustedFullNode => None,
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(tmp_db_path()), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(tmp_db_path())).unwrap());
            electrumx_wallet
        }
    };
    generate_money_for_wallet(&mut wallet, &bitcoind_client, BlockChainProvider::Electrumx);

    // generate destination address
    // lock all utxos
    // unlock some of them
    // try to lock again
    // should work without errors
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    wallet.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    wallet.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    let (_, lock_id) = wallet.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    wallet.wallet_lib_mut().unlock_coins(lock_id);

    let (tx, _) = wallet.send_coins(
        dest_addr,
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    wallet.publish_tx(&tx);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

fn lock_coins_flag_fail(provider: BlockChainProvider) {
    // initialize bitcoind docker container
    // it will be destroyed automatically when appropriate object goes out of scope
    let docker = DockerCli::new();
    let node = docker.run(BitcoinCore::default());
    let (bitcoind_client, cfg, host_port) = bitcoind_init(&node);
    let mut electrs_process = match provider {
        BlockChainProvider::TrustedFullNode => None,
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // initialize wallet with blockchain source and generated money
    let mut wallet = match provider {
        BlockChainProvider::TrustedFullNode => {
            let bio = Box::new(BitcoinCoreIO::new(
                BitcoinCoreClient::new(&cfg.url, &cfg.user, &cfg.password)));
            let mut default_wallet: Box<Wallet> = Box::new(WalletWithTrustedFullNode::new_no_random(
                WalletConfig::with_db_path(tmp_db_path()), bio).unwrap());
            default_wallet
        }
        BlockChainProvider::Electrumx => {
            let mut electrumx_wallet: Box<Wallet> = Box::new(ElectrumxWallet::new_no_random(
                WalletConfig::with_db_path(tmp_db_path())).unwrap());
            electrumx_wallet
        }
    };
    generate_money_for_wallet(&mut wallet, &bitcoind_client, BlockChainProvider::Electrumx);

    // generate destination address
    // lock all utxos
    // try to lock again
    // should finish with error
    let dest_addr = wallet.wallet_lib_mut().new_address(AccountAddressType::P2WKH).unwrap();
    wallet.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    wallet.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();
    wallet.send_coins(
        dest_addr.clone(),
        200_000_000 - 10_000,
        true,
        false,
        false,
    ).unwrap();

    // should finish with error, no available coins left
    let result = wallet.send_coins(
        dest_addr,
        200_000_000 - 10_000,
        false,
        false,
        true,
    );
    assert!(result.is_err());

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

// TODO(evg): tests for lock persistence
// TODO(evg): tests for witness_only flag

fn launch_electrs_process(cookie: String, daemon_rpc_addr: String, network: String, db_dir: String) -> Child {
    let mut electrs_process = Command::new("electrs")
        .arg("--jsonrpc-import")
        .arg(format!("--cookie={}", cookie))
        .arg(format!("--daemon-rpc-addr={}", daemon_rpc_addr))
        .arg(format!("--network={}", network))
        .arg(format!("--db-dir={}", db_dir))
        .spawn()
        .expect("Failed to execute command");
    electrs_process
}