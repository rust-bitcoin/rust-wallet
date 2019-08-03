//
// Copyright 2018 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(unused_must_use)]
#![forbid(unsafe_code)]

extern crate crypto;
extern crate secp256k1;
extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate rand;
#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate serde_json;

extern crate serde;
#[macro_use] extern crate serde_derive;

pub mod mnemonic;
pub mod error;
pub mod context;
pub mod masteraccount;
pub mod account;
pub mod wallet;
pub mod proved;
pub mod trunk;
