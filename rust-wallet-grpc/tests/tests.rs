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
extern crate bitcoin_core_io;

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
use rand::{
    Rng, thread_rng,
    distributions::Alphanumeric,
};

use std::{
    str::FromStr,
    thread,
    time::Duration,
    process::{Command, Child},
};

use wallet::{
    walletlibrary::{WalletConfig, BitcoindConfig, WalletLibraryMode, KeyGenConfig},
    default::WalletWithTrustedFullNode,
    electrumx::ElectrumxWallet,
    interface::Wallet,
};
use rust_wallet_grpc::{
    server::{launch_server_new, DEFAULT_WALLET_RPC_PORT},
    client::WalletClientWrapper,
    walletrpc::{AddressType, OutPoint as RpcOutPoint},
};
use bitcoin_core_io::BitcoinCoreIO;

const LAUNCH_SERVER_DELAY_MS: u64 = 3000;
const SHUTDOWN_SERVER_DELAY_MS: u64 = 2000;

const ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS: u64 = 5000;
const LAUNCH_ELECTRUMX_SERVER_DELAY_MS: u64 = 500;

fn bitcoind_init(
    node: &Container<DockerCli, BitcoinCore>,
) -> (BitcoinCoreClient, BitcoindConfig, u32) {
    let host_port = node.get_host_port(18443).unwrap();
    let zmq_port = node.get_host_port(18501).unwrap();
    let url = format!("http://localhost:{}", host_port);
    let auth = node.image().auth();
    let bitcoind_client = BitcoinCoreClient::new(url.as_str(), auth.username(), auth.password());
    let cfg = BitcoindConfig::new(
        url,
        auth.username().to_owned(),
        auth.password().to_owned(),
        format!("tcp://localhost:{}", zmq_port),
        format!("tcp://localhost:{}", zmq_port),
    );

    (bitcoind_client, cfg, host_port)
}

fn launch_server_and_wait_new(
    db_path: String,
    cfg: BitcoindConfig,
    provider: BlockChainProvider,
    mode: WalletLibraryMode,
) -> WalletClientWrapper {
    let provider_copy = provider.clone();
    thread::spawn(move || {
        let wallet: Box<dyn Wallet + Send> = match provider_copy {
            BlockChainProvider::TrustedFullNode => {
                let bio = Box::new(BitcoinCoreIO::new(BitcoinCoreClient::new(
                    &cfg.url,
                    &cfg.user,
                    &cfg.password,
                )));
                let (default_wallet, _) =
                    WalletWithTrustedFullNode::new(WalletConfig::with_db_path(db_path), bio, mode)
                        .unwrap();
                Box::new(default_wallet)
            }
            BlockChainProvider::Electrumx => {
                let (electrumx_wallet, _) =
                    ElectrumxWallet::new(WalletConfig::with_db_path(db_path), mode).unwrap();
                Box::new(electrumx_wallet)
            }
        };
        launch_server_new(wallet, DEFAULT_WALLET_RPC_PORT);
    });
    thread::sleep(Duration::from_millis(LAUNCH_SERVER_DELAY_MS));
    let client = WalletClientWrapper::new(DEFAULT_WALLET_RPC_PORT);
    client
}

fn shutdown_and_wait(client: &WalletClientWrapper) {
    client.shutdown();
    thread::sleep(Duration::from_millis(SHUTDOWN_SERVER_DELAY_MS));
}

fn restart_wallet_new(
    client: &WalletClientWrapper,
    db_path: String,
    cfg: BitcoindConfig,
    provider: BlockChainProvider,
    mode: WalletLibraryMode,
) -> WalletClientWrapper {
    shutdown_and_wait(&client);
    let client = launch_server_and_wait_new(db_path.clone(), cfg.clone(), provider.clone(), mode);
    client
}

fn tmp_db_path() -> String {
    let mut rez: String = "/tmp/test_".to_string();
    let suffix: String = thread_rng().sample_iter(&Alphanumeric).take(10).collect();
    rez.push_str(&suffix);
    rez
}

#[derive(PartialEq, Clone)]
enum BlockChainProvider {
    TrustedFullNode,
    Electrumx,
}

fn generate_money_for_wallet(
    client: &WalletClientWrapper,
    bitcoind_client: &BitcoinCoreClient,
    provider: BlockChainProvider,
) {
    // generate money to p2pkh addresses
    let addr = client.new_address(AddressType::P2PKH);
    let change_addr = client.new_change_address(AddressType::P2PKH);
    bitcoind_client
        .send_to_address(&Address::from_str(&addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();
    bitcoind_client
        .send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();

    // generate money to p2shwh addresses
    let addr = client.new_address(AddressType::P2SHWH);
    let change_addr = client.new_change_address(AddressType::P2SHWH);
    bitcoind_client
        .send_to_address(&Address::from_str(&addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();
    bitcoind_client
        .send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();

    // generate money to p2wkh addresses
    let addr = client.new_address(AddressType::P2WKH);
    let change_addr = client.new_change_address(AddressType::P2WKH);
    bitcoind_client
        .send_to_address(&Address::from_str(&addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();
    bitcoind_client
        .send_to_address(&Address::from_str(&change_addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();

    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));
    }
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 600_000_000);
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
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server and initialize wallet client
    let client = launch_server_and_wait_new(
        tmp_db_path(),
        cfg,
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );

    // generate wallet address and send money to it
    // sync with blockchain
    // check wallet balance
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client
        .send_to_address(&Address::from_str(&addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));
    }
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 100_000_000);

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
    shutdown_and_wait(&client);
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
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait_new(
        tmp_db_path(),
        cfg,
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );
    generate_money_for_wallet(&client, &bitcoind_client, provider.clone());

    // select all available utxos
    // generate destination address
    // check that generated transaction valid and can be send to blockchain
    let ops: Vec<RpcOutPoint> = client
        .get_utxo_list()
        .iter_mut()
        .map(|utxo| utxo.take_out_point())
        .collect();
    let dest_addr = client.new_address(AddressType::P2WKH);
    let encoded_tx = client.make_tx(ops, dest_addr, 150_000_000, true);
    let tx: Transaction = deserialize(&encoded_tx).unwrap();
    bitcoind_client
        .get_raw_transaction_serialized(&tx.txid())
        .unwrap()
        .unwrap();

    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
    shutdown_and_wait(&client);
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
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server and initialize wallet client
    let client = launch_server_and_wait_new(
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );

    // generate wallet address and send money to it
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client
        .send_to_address(&Address::from_str(&addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));
    }
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 100_000_000);

    // shutdown wallet and recover wallet's state from persistent storage
    // restart_wallet(&client, db_path, cfg);
    let client = restart_wallet_new(
        &client,
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Decrypt,
    );

    // balance should not change after restart
    assert_eq!(client.wallet_balance(), 100_000_000);

    // wallet should remain viable after restart, so try to make some ordinary actions
    // and check wallet's state
    let addr = client.new_address(AddressType::P2WKH);
    bitcoind_client
        .send_to_address(&Address::from_str(&addr).unwrap(), 1.0)
        .unwrap()
        .unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));
    }
    client.sync_with_tip();
    assert_eq!(client.wallet_balance(), 200_000_000);

    shutdown_and_wait(&client);
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
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait_new(
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );
    generate_money_for_wallet(&client, &bitcoind_client, provider.clone());

    // shutdown wallet and recover wallet's state from persistent storage
    let client = restart_wallet_new(
        &client,
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Decrypt,
    );

    // select all available utxos
    // generate destination address
    // spend selected utxos
    let dest_addr = client.new_address(AddressType::P2WKH);
    let ops: Vec<RpcOutPoint> = client
        .get_utxo_list()
        .iter_mut()
        .map(|utxo| utxo.take_out_point())
        .collect();
    let encoded_tx = client.make_tx(ops, dest_addr, 150_000_000, true);
    let tx: Transaction = deserialize(&encoded_tx).unwrap();
    bitcoind_client
        .get_raw_transaction_serialized(&tx.txid())
        .unwrap()
        .unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    // It seems that electrumx server has some bugs so we should to restart it time-to-time
    // TODO(evg): find out and fix problem in electrumx server
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));

        electrs_process.unwrap().kill().unwrap();
        electrs_process = Some(launch_electrs_process(
            format!("{}:{}", cfg.user, cfg.password),
            format!("127.0.0.1:{}", host_port),
            "regtest".to_string(),
            tmp_db_path(),
        ));
        thread::sleep(Duration::from_millis(LAUNCH_ELECTRUMX_SERVER_DELAY_MS));
        // reconnect after electrumx server restarting
        // wallet.reconnect();
        restart_wallet_new(
            &client,
            db_path.clone(),
            cfg.clone(),
            provider.clone(),
            WalletLibraryMode::Decrypt,
        );
    }
    client.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    // shutdown wallet and recover wallet's state from persistent storage
    let client = restart_wallet_new(
        &client,
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Decrypt,
    );

    // balance should not change after restart
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    shutdown_and_wait(&client);
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
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait_new(
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );
    generate_money_for_wallet(&client, &bitcoind_client, provider.clone());

    // select utxo subset
    // generate destination address
    // spend selected utxo subset
    let ops = client
        .get_utxo_list()
        .iter_mut()
        .take(2)
        .map(|utxo| utxo.take_out_point())
        .collect();
    let dest_addr = client.new_address(AddressType::P2WKH);
    client.make_tx(ops, dest_addr, 150_000_000, true);
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));

        electrs_process.unwrap().kill().unwrap();
        electrs_process = Some(launch_electrs_process(
            format!("{}:{}", cfg.user, cfg.password),
            format!("127.0.0.1:{}", host_port),
            "regtest".to_string(),
            tmp_db_path(),
        ));
        thread::sleep(Duration::from_millis(LAUNCH_ELECTRUMX_SERVER_DELAY_MS));
        // reconnect after electrumx server restarting
        // wallet.reconnect();
        restart_wallet_new(
            &client,
            db_path.clone(),
            cfg.clone(),
            provider.clone(),
            WalletLibraryMode::Decrypt,
        );
    }
    client.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = client
        .get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);

    shutdown_and_wait(&client);
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
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    let db_path = tmp_db_path();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait_new(
        db_path.clone(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );
    generate_money_for_wallet(&client, &bitcoind_client, provider.clone());

    // generate destination address
    // send coins to itself
    // sync with blockchain
    let dest_addr = client.new_address(AddressType::P2WKH);
    client
        .send_coins(dest_addr, 150_000_000, true, false)
        .unwrap();
    bitcoind_client.generate(1).unwrap().unwrap();
    if provider == BlockChainProvider::Electrumx {
        thread::sleep(Duration::from_millis(
            ELECTRUMX_SERVER_SYNC_WITH_BLOCKCHAIN_DELAY_MS,
        ));

        electrs_process.unwrap().kill().unwrap();
        electrs_process = Some(launch_electrs_process(
            format!("{}:{}", cfg.user, cfg.password),
            format!("127.0.0.1:{}", host_port),
            "regtest".to_string(),
            tmp_db_path(),
        ));
        thread::sleep(Duration::from_millis(LAUNCH_ELECTRUMX_SERVER_DELAY_MS));
        // reconnect after electrumx server restarting
        // wallet.reconnect();
        restart_wallet_new(
            &client,
            db_path.clone(),
            cfg.clone(),
            provider.clone(),
            WalletLibraryMode::Decrypt,
        );
    }
    client.sync_with_tip();

    // wallet send money to itself, so balance decreased only by fee
    assert_eq!(client.wallet_balance(), 600_000_000 - 10_000);

    // we should be able to find utxo with change of previous transaction
    let ok = client
        .get_utxo_list()
        .iter()
        .any(|utxo| utxo.value == 200_000_000 - 150_000_000 - 10_000);
    assert!(ok);

    shutdown_and_wait(&client);
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
    let electrs_process = match provider {
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait_new(
        tmp_db_path(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );
    generate_money_for_wallet(&client, &bitcoind_client, provider.clone());

    // generate destination address
    // lock all utxos
    // unlock some of them
    // try to lock again
    // should work without errors
    let dest_addr = client.new_address(AddressType::P2WKH);
    client
        .send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true)
        .unwrap();
    client
        .send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true)
        .unwrap();
    let (_, lock_id) = client
        .send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true)
        .unwrap();
    client.unlock_coins(lock_id);

    client
        .send_coins(dest_addr, 200_000_000 - 10_000, true, true)
        .unwrap();

    shutdown_and_wait(&client);
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
    let electrs_process = match provider {
        BlockChainProvider::Electrumx => {
            let mut electrs_process = launch_electrs_process(
                format!("{}:{}", cfg.user, cfg.password),
                format!("127.0.0.1:{}", host_port),
                "regtest".to_string(),
                tmp_db_path(),
            );
            Some(electrs_process)
        }
        BlockChainProvider::TrustedFullNode => None,
    };
    bitcoind_client.generate(110).unwrap().unwrap();

    // launch wallet server with generated money and initialize wallet client
    let client = launch_server_and_wait_new(
        tmp_db_path(),
        cfg.clone(),
        provider.clone(),
        WalletLibraryMode::Create(KeyGenConfig::default()),
    );
    generate_money_for_wallet(&client, &bitcoind_client, provider.clone());

    // generate destination address
    // lock all utxos
    // try to lock again
    // should finish with error
    let dest_addr = client.new_address(AddressType::P2WKH);
    client
        .send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true)
        .unwrap();
    client
        .send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true)
        .unwrap();
    client
        .send_coins(dest_addr.clone(), 200_000_000 - 10_000, false, true)
        .unwrap();

    // should panic, no available coins left
    let result = client.send_coins(dest_addr, 200_000_000 - 10_000, true, false);
    assert!(result.is_err());

    shutdown_and_wait(&client);
    if provider == BlockChainProvider::Electrumx {
        electrs_process.unwrap().kill().unwrap();
    }
}

// TODO(evg): tests for lock persistence
// TODO(evg): tests for witness_only flag

fn launch_electrs_process(
    cookie: String,
    daemon_rpc_addr: String,
    network: String,
    db_dir: String,
) -> Child {
    let electrs_process = Command::new("electrs")
        .arg("--jsonrpc-import")
        .arg(format!("--cookie={}", cookie))
        .arg(format!("--daemon-rpc-addr={}", daemon_rpc_addr))
        .arg(format!("--network={}", network))
        .arg(format!("--db-dir={}", db_dir))
        .spawn()
        .expect("Failed to execute command");
    electrs_process
}
