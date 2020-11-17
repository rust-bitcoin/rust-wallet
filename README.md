[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
# Bitcoin Wallet Library in Rust
This is a library to build Bitcoin wallets with Rust. 
It uses BIP32 key derivation, BIP39 mnemonics and BIP44, BIP48, BIP84 key 
hierarchy which makes it compatible to TREZOR, Ledger and many other
wallets.

This library supports SLIP-0039 Shamir's Shared Secret Scheme as available in TREZOR Model T

It supports legacy P2PKH, transitional P2SHWPKH and native segwit P2WPKH for single key signatures
and native P2WSH for arbitrary sripts.

## Basic Accounts Use
`MasterAccount` holds an encrypted seed that implies the BIP32 root key. Add any number of `Account` to it to derive 
hiararchies following BIP44. An Account will have addresses of a uniform type. 
```rust
const PASSPHRASE: &str = "correct horse battery staple";

// create a new random master account. This holds the root BIP32 key
// PASSPHRASE is used to encrypt the seed in memory and in storage
let mut master = MasterAccount::new(MasterKeyEntropy::Sufficient, Network::Bitcoin, PASSPHRASE).unwrap();

// or re-create a master from a known mnemonic
let words = "announce damage viable ticket engage curious yellow ten clock finish burden orient faculty rigid smile host offer affair suffer slogan mercy another switch park";
let mnemonic = Mnemonic::from_str(words).unwrap();
// PASSPHRASE is used to encrypt the seed in memory and in storage
// last argument is option password for plausible deniability
let mut master = MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();

// The master accounts only store public keys
// Private keys are created on-demand from encrypted seed with an Unlocker and forgotten as soon as possible

// create an unlocker that is able to decrypt the encrypted mnemonic and then calculate private keys
let mut unlocker = Unlocker::new_for_master(&master, PASSPHRASE).unwrap();

// The unlocker is needed to create accounts within the master account as 
// key derivation follows BIP 44, which requires private key derivation

// create a P2PKH (pay-to-public-key-hash) (legacy) account. 
// account number 0, sub-account 0 (which usually means receiver) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2PKH, 0, 0, 10).unwrap();
master.add_account(account);

// create a P2SHWPKH (pay-to-script-hash-witness-public-key-hash) (transitional single key segwit) account.
// account number 0, sub-account 1 (which usually means change) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 1, 10).unwrap();
master.add_account(account);

// create a P2WPKH (pay-to-witness-public-key-hash) (native single key segwit) account.
// account number 1, sub-account 0 (which usually means receiver) BIP32 look-ahead 10
let account = Account::new(&mut unlocker, AccountAddressType::P2WPKH, 1, 0, 10).unwrap();
master.add_account(account);
// account number 1, sub-account 1 (which usually means change) BIP32 look-ahead 10
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

const RBF: u32 = 0xffffffff - 2;

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
```rust
const CSV:u16 = 10; // 10 blocks relative lock

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
```rust
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
## Shamir's Secret Shares
```rust
// create an new random account        
let master = MasterAccount::new(MasterKeyEntropy::Low, Network::Bitcoin, PASSPHRASE).unwrap();

// extract seed
let seed = master.seed(Network::Bitcoin, PASSPHRASE).unwrap();

// cut seed into 5 shares such that any 3 of them is sufficient to re-construct
let shares = ShamirSecretSharing::generate(1, &[(3,5)], &seed, None, 1).unwrap();

// re-construct seed from the first 3
let reconstructed_seed = ShamirSecretSharing::combine(&shares[..3], None).unwrap();

// re-construct master from seed
let reconstructed_master = MasterAccount::from_seed(&reconstructed_seed, 0, Network::Bitcoin, PASSPHRASE).unwrap();

// prove that everything went fine
assert_eq!(master.master_public(), reconstructed_master.master_public());
assert_eq!(master.encrypted(), reconstructed_master.encrypted());
```
