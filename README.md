[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
# Bitcoin Wallet Library in Rust
This is a library to build Bitcoin wallets with Rust. 
It uses BIP32 key derivation, BIP39 mnemonics and BIP44, BIP48, BIP84 key 
hierarchy which makes it compatible to TREZOR, Ledger and many other
wallets.

It supports legacy P2PKH, transitional P2SHWPKH and native segwit P2WPKH for single key signatures
and native P2WSH for arbitrary sripts.

## Basic Accounts Use
```
const PASSPHRASE: &str = "correct horse battery staple";

// create a new random master account. This holds the root BIP32 key
let mut master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, PASSPHRASE, None).unwrap();

// or re-create a master from a known mnemonic
let words = "announce damage viable ticket engage curious yellow ten clock finish burden orient faculty rigid smile host offer affair suffer slogan mercy another switch park";
let mnemonic = Mnemonic::from_str(words).unwrap();
let mut master = MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();

// or re-create a master from encrypted storage that holds AES encrypted mnemonic, master public key and the birth time point of the key (seconds in Unix epoch)
let mut master = MasterAccount::from_encrypted(
            hex::decode("0e05ba48bb0fdc7285dc9498202aeee5e1777ac4f55072b30f15f6a8632ad0f3fde1c41d9e162dbe5d3153282eaebd081cf3b3312336fc56f5dd18a2df6ea48c1cdd11a1ed11281cd2e0f864f02e5bed5ab03326ed24e43b8a184acff9cb4e730db484e33f2b24295a97b2ca87871a69384eb64d4160ce8b3e8b4d90234040970e531d4333a8979dbe533c2b2668bf43b6607b2d24c5b42765ebfdd075fd173c").unwrap().as_slice(),
            ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4XKz4vgwBmnnVmA7EgWhnXvimQ4krq94yUgcSSbroi4uC1xbZ3UGMxG9M2utmaPjdpMrWW2uKRY9Mj4DZWrrY8M4pry8shsK").unwrap(),
            1567260002);

// The master accounts only store public keys
// Private keys are created on-demand with an Unlocker and forgotten as soon as possible

// create an unlocker that is able to decrypt the encripted mnemonic and then calculate private keys
let mut unlocker = Unlocker::new_for_master(&master, PASSPHRASE, None).unwrap();

// The unlocker is needed to create accounts within the master account as 
// key derivation follows BIP 44, which requires private key derivation

// create a P2PKH (pay-to-public-key-hash) (legacy) account. 
// account number 0, sub-account 0 (which usually means receiver) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, 10).unwrap();
master.add_account(account);

// create a P2SHWPKH (pay-to-script-hash-witness-public-key-hash) (transitional single key segwit) account.
// account number 0, sub-account 1 (which usually means change) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 1, 10).unwrap();
master.add_account(account);

// create a P2WPKH (pay-to-witness-public-key-hash) (native single key segwit) account.
// account number 1, sub-account 0 (which usually means receiver) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2WPKH, 1, 0, 10).unwrap();
master.add_account(account);
// account number 1, sub-account 0 (which usually means change) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2WPKH, 1, 1, 10).unwrap();
master.add_account(account);

// get next legacy receiver address
let source = master.get_mut((0,0)).unwrap().next_key().unwrap().address.clone();
// pay to some native segwit address
let target = master.get_mut((1,0)).unwrap().next_key().unwrap().address.clone();
// change to some transitional address
let change = master.get_mut((0,1)).unwrap().next_key().unwrap().address.clone();

// a dummy transaction to send to source
let input_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: sha256d::Hash::default(), vout: 0 },
                    sequence: RBF,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: source.script_pubkey(),
                    value: 5000000000,
                }
            ],
            lock_time: 0,
            version: 2,
        };

let txid = input_transaction.txid();

// a dummy transaction that spends source
let mut spending_transaction = Transaction {
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    sequence: RBF,
                    witness: Vec::new(),
                    script_sig: Script::new(),
                }
            ],
            output: vec![
                TxOut {
                    script_pubkey: target.script_pubkey(),
                    value: 4000000000,
                },
                TxOut {
                    script_pubkey: change.script_pubkey(),
                    value: 999999000,
                }
            ],
            lock_time: 0,
            version: 2,
        };

// helper to find previous outputs
let mut spent = HashMap::new();
spent.insert(txid, input_transaction.clone());

// sign the spend
master.sign(&mut spending_transaction, SigHashType::All,
                       &(|_| Some(input_transaction.output[0].clone())), 
            &mut unlocker).expect("can not sign");

// verify the spend with the bitcoinconsensus library
spending_transaction.verify(|point|
            spent.get(&point.txid).and_then(|t| t.output.get(point.vout as usize).cloned())
        ).expect("Bitcoin Core would not like this")
```
## Advanced Accounts Use
```
// create a P2WSH (pay-to-witness-script-hash) (native segwit for arbitrary scripts) account
let account = Account::new(&mut unlocker, AccountAddressType::P2WSH(4711), 2, 0, 0).unwrap();
master.add_account(account);
{
    let account = master.get_mut((2, 0)).unwrap();
    let scripter = |pk: &PublicKey, csv: Option<u16>| Builder::new()
        .push_int(csv.unwrap() as i64)
        .push_opcode(all::OP_CSV)
        .push_opcode(all::OP_DROP)
        .push_slice(pk.to_bytes().as_slice())
        .push_opcode(all::OP_CHECKSIG)
        .into_script();
    account.add_script_key(scripter, Some(&[0x01; 32]), Some(CSV)).unwrap();
}

```
## Coins use
```
// create a coin store
let mut coins = Coins::new();

// put all coins from block into coin store that are ours (means master can sign for them)
coins.process(&mut master, &block);

// calculate balances
let confirmed = coins.confirmed_balance();
let unconfirmed = coins.unconfirmed_balance();
// means not OP_CSV time locked
let available = coins.available_balance();

// undo the highest block as it was removed through re-org
coins.unwind_tip(block_hash);

// choose inputs to spend
let inputs = choose_inputs (minimum_amount_needed, current_block_height, |h| height_of_block(h));

```