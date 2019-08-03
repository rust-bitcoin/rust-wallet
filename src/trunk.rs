//
// Copyright 2019 Tamas Blummer
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
//!
//! # Access to trunk
//!
//!

use bitcoin::BlockHeader;
use bitcoin_hashes::sha256d;

/// access the current trunk (longest chain of headers as defined by POW)
pub trait Trunk {
    fn is_on_trunk (&self, block_hash: &sha256d::Hash) -> bool;
    fn get_header (&self, block_hash: &sha256d::Hash) -> Option<BlockHeader>;
    fn get_height (&self, block_hash: &sha256d::Hash) -> Option<u32>;
    fn get_tip (&self) -> Option<BlockHeader>;
    fn len(&self) -> u32;
}
