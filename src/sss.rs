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
//! # Shamir's Secret Sharing as defined by SLIP-0039
//! see https://github.com/satoshilabs/slips/blob/master/slip-0039.md
//!
use bitcoin::util::bip158::{BitStreamWriter, BitStreamReader};
use error::Error;
use std::io::Cursor;
use crypto::pbkdf2::pbkdf2;
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use rand::{thread_rng, RngCore};
use crypto::mac::Mac;
use std::collections::{HashSet, HashMap};

const RADIX_BITS: usize = 10; // The length of the radix in bits.

const RADIX: usize = 1 << RADIX_BITS; // The number of words in the word list.

const ID_LENGTH_BITS: usize = 15; // The length of the random identifier in bits.

const ITERATION_EXP_LENGTH_BITS: usize = 5; // The length of the iteration exponent in bits.

const fn bits_to_words(n: usize) -> usize { (n + RADIX_BITS - 1) / RADIX_BITS }

const ID_EXP_LENGTH_WORDS: usize = bits_to_words(ID_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS); // The length of the random identifier and iteration exponent in words.

const MAX_SHARE_COUNT: u8 = 16; // The maximum number of shares that can be created.

const CHECKSUM_LENGTH_WORDS: usize = 3; // The length of the RS1024 checksum in words.

const DIGEST_LENGTH_BYTES: usize = 4; // The length of the digest of the shared secret in bytes.

const CUSTOMIZATION_STRING: &[u8;6] = b"shamir"; // The customization string used in the RS1024 checksum and in the PBKDF2 salt.

const METADATA_LENGTH_WORDS: usize = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS; // The length of the mnemonic in words without the share value.

const MIN_STRENGTH_BITS: usize = 128; // The minimum allowed entropy of the master secret.

const MIN_MNEMONIC_LENGTH_WORDS: usize = METADATA_LENGTH_WORDS + bits_to_words(MIN_STRENGTH_BITS); // The minimum allowed length of the mnemonic in words.

const BASE_ITERATION_COUNT: usize = 10000; // The minimum number of iterations to use in PBKDF2.

const ROUND_COUNT: usize = 4; // The number of rounds to use in the Feistel cipher.

const SECRET_INDEX: usize = 255; // The index of the share containing the shared secret.

const DIGEST_INDEX: usize = 254; // The index of the share containing the digest of the shared secret.

pub struct ShamirSecretSharing {}

impl ShamirSecretSharing {
    pub fn generate (group_threshold: u8, groups: &[(u8, u8)], secret: &[u8], passphrase: Option<&str>, iteration_exponent: u8) -> Result<Vec<Share>, Error> {
        if secret.len() * 8 < MIN_STRENGTH_BITS || secret.len() % 2 != 0 {
            return Err(Error::Unsupported("master key entropy must be at least 128 bits and multiple of 16 bits"));
        }
        if group_threshold > MAX_SHARE_COUNT {
            return Err(Error::Unsupported("more than 16 groups are not supported"));
        }
        if group_threshold as usize > groups.len() {
            return Err(Error::Unsupported("group threshold should not exceed number of groups"));
        }
        if groups.iter().any(|(threshold, count)| *threshold == 1 && *count > 1) {
            return Err(Error::Unsupported("can only generate one share for threshold = 1"));
        }
        if groups.iter().any(|(threshold, count)| *threshold > *count) {
            return Err(Error::Unsupported("number of shares must not be less than threshold"));
        }
        let id = (thread_rng().next_u32() % (((1<<(ID_LENGTH_BITS+1))-1) as u32)) as u16;
        let mut shares = Vec::new();
        for (group_index, group_share) in Self::split_secret(group_threshold, groups.len() as u8,
                                                       Self::encrypt(id, iteration_exponent, secret, passphrase)?.as_slice())? {
            let (member_threshold, count) = groups[group_index as usize];
            for (member_index, value) in Self::split_secret(member_threshold, count, group_share.as_slice())? {
                shares.push(Share {id, value, iteration_exponent, group_count: groups.len() as u8,
                    group_index, group_threshold, member_index, member_threshold});
            }
        }
        Ok(shares)
    }

    pub fn combine(shares: &[Share], passphrase: Option<&str>) -> Result<Vec<u8>, Error> {
        let (id, iteration_exponent, group_threshold, groups) = Self::preprocess(shares)?;
        if groups.len() < group_threshold as usize {
            return Err(Error::Unsupported("need shares from more groups to reconstruct secret"));
        }
        if groups.len() != group_threshold as usize {
            return Err(Error::Unsupported("shares from too many groups"));
        }
        if groups.iter().any(|(_, group)| group[0].0 as usize != group.len()) {
            return Err(Error::Unsupported("for every group number of member shares should match member threshold"));
        }
        if groups.iter().any(|(_, g)|
            g.iter().fold(HashSet::new(), |mut a, v| {a.insert(v.0); a}).len() > 1) {
            return Err(Error::Unsupported("member threshold must be the same within a group"));
        }
        let mut group_secrets = Vec::new();
        for (group_index, group) in groups {
            group_secrets.push((group_index, Self::recover_secret(group[0].0, group.iter().map(|(_,m, v)| (*m, v.clone())).collect::<Vec<_>>().as_slice())?));
        }
        Self::decrypt(id, iteration_exponent, Self::recover_secret(group_threshold, group_secrets.as_slice())?.as_slice(), passphrase)
    }

    fn preprocess (shares: &[Share]) -> Result<(u16, u8, u8, HashMap<u8, Vec<(u8, u8, Vec<u8>)>>), Error> {
        if shares.len () < 1 {
            return Err(Error::Unsupported("need at least one share to reconstruct secret"));
        }
        let identifiers = shares.iter().map(|s| s.id).collect::<HashSet<_>>();
        if identifiers.len () > 1 {
            return Err(Error::Unsupported("shares do not belong to the same secret"));
        }
        let iteration_exponents = shares.iter().map(|s| s.iteration_exponent).collect::<HashSet<_>>();
        if iteration_exponents.len () > 1 {
            return Err(Error::Unsupported("shares do not have the same iteration exponent"));
        }
        let group_thresholds = shares.iter().map(|s| s.group_threshold).collect::<HashSet<_>>();
        if group_thresholds.len () > 1 {
            return Err(Error::Unsupported("shares do not have the same group threshold"));
        }
        let group_counts = shares.iter().map(|s| s.group_count).collect::<HashSet<_>>();
        if group_counts.len () > 1 {
            return Err(Error::Unsupported("shares do not have the same group count"));
        }
        if shares.iter().any(|s| s.group_threshold > s.group_count) {
            return Err(Error::Unsupported("greater group threshold than group counts"));
        }
        let mut groups = HashMap::new();
        for share in shares {
            groups.entry(share.group_index).or_insert(Vec::new())
                .push((share.member_threshold, share.member_index, share.value.clone()));
        }
        return Ok((identifiers.iter().next().unwrap().clone(),
                iteration_exponents.iter().next().unwrap().clone(),
                group_thresholds.iter().next().unwrap().clone(),
                groups))
    }

    fn recover_secret(threshold: u8, shares: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, Error> {
        if threshold == 1 {
            return Ok(shares[0].1.clone());
        }
        let shared_secret = Self::interpolate(shares, SECRET_INDEX as u8)?;
        let digest_share = Self::interpolate(shares, DIGEST_INDEX as u8)?;
        if &digest_share[..DIGEST_LENGTH_BYTES] != Self::share_digest(&digest_share[DIGEST_LENGTH_BYTES..], shared_secret.as_slice()).as_slice() {
            return Err(Error::Unsupported("share digest incorrect"));
        }
        Ok(shared_secret)
    }

    fn split_secret (threshold: u8, share_count: u8, shared_secret: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Error> {
        if threshold < 1 {
            return Err(Error::Unsupported("sharing threshold must be > 1"));
        }

        if share_count > MAX_SHARE_COUNT {
            return Err(Error::Unsupported("too many shares"));
        }

        if threshold > share_count {
            return Err(Error::Unsupported("number of shares should be at least equal threshold"));
        }

        let mut shares = Vec::new();

        if threshold == 1 {
            for i in 0 .. share_count {
                shares.push((i, shared_secret.to_vec()));
            }
            return Ok(shares);
        }

        let random_shares_count = std::cmp::max(threshold - 2, 0);

        for i in 0 .. random_shares_count {
            let mut share = vec!(0u8; shared_secret.len());
            thread_rng().fill_bytes(share.as_mut_slice());
            shares.push((i, share));
        }

        let mut base_shares = shares.clone();
        let mut random_part = vec!(0u8; shared_secret.len() - DIGEST_LENGTH_BYTES);
        thread_rng().fill_bytes(random_part.as_mut_slice());
        let mut digest = Self::share_digest(random_part.as_slice(), shared_secret);
        digest.extend_from_slice(random_part.as_slice());
        base_shares.push((DIGEST_INDEX as u8, digest));
        base_shares.push((SECRET_INDEX as u8, shared_secret.to_vec()));

        for i in random_shares_count .. share_count {
            shares.push((i, Self::interpolate(base_shares.as_slice(), i)?));
        }

        Ok(shares)
    }

    fn interpolate(shares: &[(u8, Vec<u8>)], x: u8) -> Result<Vec<u8>, Error> {
        let x_coordinates = shares.iter().map(|(i, _)|*i).collect::<HashSet<_>>();
        if x_coordinates.len() != shares.len() {
            return Err(Error::Unsupported("need unique shares for interpolation"));
        }
        if shares.len () < 1 {
            return Err(Error::Unsupported("need at least one share for interpolation"));
        }
        let len = shares[0].1.len();
        if shares.iter().any(|s| s.1.len() != len) {
            return Err(Error::Unsupported("shares should have equal length"));
        }
        if x_coordinates.contains(&x) {
            return Ok(shares.iter().find_map(|(i, v)| if *i == x {Some (v.clone())} else {None}).unwrap())
        }

        #[inline]
        fn mod_255(mut n: i16) -> i16 {
            while n < 0 {
                n += 255;
            }
            n % 255
        }

        let log_prod = shares.iter().map(|(i, _)| Self::LOG[(*i ^ x) as usize]).fold(0i16, |a, v| a + v as i16);
        let mut result = vec!(0u8; len);
        for (i, share) in shares {
            let log_basis = mod_255(
                log_prod
                    - Self::LOG[(*i ^ x) as usize] as i16
                    - shares.iter().map(|(j, _)| Self::LOG[(*j ^ *i) as usize]).fold(0i16, |a, v| a + v as i16) as i16);
            result.iter_mut().zip(share.iter())
                .for_each(|(r, s)|
                    *r ^= if *s != 0 {
                         Self::EXP[mod_255(Self::LOG[*s as usize] as i16 + log_basis) as usize]
                    } else {0});
        }
        Ok(result)
    }

    fn share_digest(random: &[u8], shared_secret: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::new(Sha256::new(), random);
        mac.input(shared_secret);
        mac.result().code()[..4].to_vec()
    }

    // encrypt master with a passphrase
    fn encrypt(id: u16, iteration_exponent: u8, master: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, Error> {
        Self::checkpass(passphrase)?;
        Ok(Self::crypt(id, iteration_exponent, master,
                       (0 .. ROUND_COUNT).map(|n| n as u8).collect::<Vec<_>>().as_slice(),
                       passphrase.unwrap_or("")))
    }

    // decrypt master with a passphrase
    fn decrypt(id: u16, iteration_exponent: u8, master: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, Error> {
        Self::checkpass(passphrase)?;
        Ok(Self::crypt(id, iteration_exponent, master,
                       (0 .. ROUND_COUNT).rev().map(|n| n as u8).collect::<Vec<_>>().as_slice(),
                       passphrase.unwrap_or("")))
    }

    // check if password is only printable ascii
    fn checkpass (passphrase: Option<&str>) -> Result<(), Error> {
        if let Some(p) = passphrase {
            if p.as_bytes().iter().any(|b| *b < 32 || *b > 126) {
                return Err(Error::Unsupported("passphrase should only contain printable ASCII"));
            }
        }
        Ok(())
    }

    // encrypt of decrypt depending on range order
    fn crypt(id: u16, iteration_exponent: u8, master: &[u8], range: &[u8], passphrase: &str) -> Vec<u8> {
        let len = master.len();
        let mut left = vec!(0u8; len/2);
        let mut right = vec!(0u8; len/2);
        let mut output = vec!(0u8; len/2);

        left.as_mut_slice().copy_from_slice(&master[..len/2]);
        right.as_mut_slice().copy_from_slice(&master[len/2..]);
        for i in range {
            Self::feistel(id, iteration_exponent, *i, right.as_slice(), passphrase, &mut output);
            output.iter_mut().zip(left.iter()).for_each(|(o, l)| *o ^= *l);
            left.as_mut_slice().copy_from_slice(right.as_slice());
            right.as_mut_slice().copy_from_slice(output.as_slice());
        }
        right.extend_from_slice(left.as_slice());
        right
    }

    // a step of a Feistel network
    fn feistel(id: u16, iteration_exponent: u8, step: u8, block: &[u8], passphrase: &str, output: &mut [u8]) {
        let mut key = [step].to_vec();
        key.extend_from_slice(passphrase.as_bytes());
        let mut mac = Hmac::new(Sha256::new(), key.as_slice());
        let mut salt = "shamir".as_bytes().to_vec();
        salt.extend_from_slice(&[(id>>8) as u8, (id&0xff) as u8]);
        salt.extend_from_slice(block);
        pbkdf2(&mut mac, salt.as_slice(), ((BASE_ITERATION_COUNT/4) as u32) << (iteration_exponent as u32), output);
    }

    const EXP:[u8;255] = [1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, ];
    const LOG:[u8;256] = [0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7, ];
}

#[derive(Debug)]
pub struct Share {
    pub id: u16,
    pub iteration_exponent: u8,
    pub group_index: u8,
    pub group_threshold: u8,
    pub group_count: u8,
    pub member_index: u8,
    pub member_threshold: u8,
    pub value: Vec<u8>
}

impl Share {
    /// create from human readable representation
    pub fn from_mnemonic(mnemonic: &str) -> Result<Share, Error> {
        let words = Self::mnemonic_to_words(mnemonic)?;
        if words.len() < MIN_MNEMONIC_LENGTH_WORDS {
            return Err(Error::Mnemonic("key share mnemonic must be at least 20 words"));
        }
        if Self::checksum(words.as_slice()) != 1 {
            return Err(Error::Mnemonic("checksum failed"));
        }
        let padded_value = Self::words_to_bytes(&words[ID_EXP_LENGTH_WORDS+2 .. words.len()-CHECKSUM_LENGTH_WORDS]);
        let padding = (RADIX_BITS*(words.len()-METADATA_LENGTH_WORDS))%16;
        if padding > 8 {
            return Err(Error::Mnemonic("incorrect mnmemonic length"));
        }
        let mut cursor = Cursor::new(padded_value.as_slice());
        let mut reader = BitStreamReader::new(&mut cursor);
        if reader.read(padding as u8).unwrap() != 0 {
            return Err(Error::Mnemonic("invalid padding"));
        }
        let mut value = Vec::new();
        while let Ok(b) = reader.read(8) {
            value.push(b as u8);
        }
        let prefix = Self::words_to_bytes(&words[..ID_EXP_LENGTH_WORDS+2]);
        let mut cursor = Cursor::new(&prefix);
        let mut reader = BitStreamReader::new(&mut cursor);
        Ok(Share {
            id: reader.read(ID_LENGTH_BITS as u8).unwrap() as u16,
            iteration_exponent: reader.read(ITERATION_EXP_LENGTH_BITS as u8).unwrap() as u8,
            group_index: reader.read(4).unwrap() as u8,
            group_threshold: (reader.read(4).unwrap() + 1) as u8,
            group_count: (reader.read(4).unwrap() + 1) as u8,
            member_index: reader.read(4).unwrap() as u8,
            member_threshold: (reader.read(4).unwrap() + 1) as u8,
            value
        })
    }

    /// convert to human readable representation
    pub fn to_mnemonic (&self) -> String {
        let mut bytes = Vec::new();
        let mut writer = BitStreamWriter::new(&mut bytes);
        writer.write(self.id as u64, 15).unwrap();
        writer.write(self.iteration_exponent as u64, 5).unwrap();
        writer.write(self.group_index as u64, 4).unwrap();
        writer.write((self.group_threshold - 1) as u64, 4).unwrap();
        writer.write((self.group_count - 1) as u64, 4).unwrap();
        writer.write(self.member_index as u64, 4).unwrap();
        writer.write((self.member_threshold - 1) as u64, 4).unwrap();
        writer.flush().unwrap();
        let value_word_count = (self.value.len()*8 + RADIX_BITS - 1) / RADIX_BITS;
        let padding = value_word_count*10 - self.value.len()*8;
        let mut padded_value = Vec::new();
        let mut writer = BitStreamWriter::new(&mut padded_value);
        writer.write(0, padding as u8).unwrap();
        for v in &self.value {
            writer.write(*v as u64, 8).unwrap();
        }
        writer.flush().unwrap();
        bytes.extend_from_slice(padded_value.as_slice());
        let mut words = Self::bytes_to_words(&bytes[..]);
        words.push(0);
        words.push(0);
        words.push(0);
        let chk = Self::checksum(words.as_slice()) ^ 1;
        let len = words.len();
        for i in 0..3 {
            words[len - 3 + i] = ((chk >> (RADIX_BITS as u32 * (2 - i as u32))) & 1023) as u16;
        }
        Self::words_to_mnemonic(&words[..])
    }

    // convert from byte vector to a vector of 10 bit words
    fn bytes_to_words (bytes: &[u8]) -> Vec<u16> {
        let mut words = Vec::new();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BitStreamReader::new(&mut cursor);
        while let Ok(w) = reader.read(RADIX_BITS as u8) {
            words.push(w as u16);
        }
        words
    }

    // convert from vector of 10 bit words to byte vector
    fn words_to_bytes (words: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut writer = BitStreamWriter::new(&mut bytes);
        for w in words {
            writer.write(*w as u64, 10).unwrap();
        }
        writer.flush().unwrap();
        bytes
    }

    // convert from human readable to a vector of 10 bit words
    fn mnemonic_to_words(mnemonic: &str) -> Result<Vec<u16>, Error> {
        let mut words = Vec::new();
        for w in mnemonic.split(' ') {
            if let Ok(w) = WORDS.binary_search(&w) {
                words.push(w as u16);
            }
            else {
                return Err(Error::Mnemonic("invalid word in the key share"));
            }
        }
        Ok(words)
    }

    // convert to human readable words
    fn words_to_mnemonic(words: &[u16]) -> String {
        let mut result = String::new();
        for w in words {
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(WORDS[*w as usize]);
        }
        result
    }

    // rs1024 checksum calculator
    fn checksum(values: &[u16]) -> u32 {

        const GEN :[u32;10] = [
            0xE0E040,
            0x1C1C080,
            0x3838100,
            0x7070200,
            0xE0E0009,
            0x1C0C2412,
            0x38086C24,
            0x3090FC48,
            0x21B1F890,
            0x3F3F120,
        ];

        let mut chk = 1u32;
        for v in CUSTOMIZATION_STRING.iter().map(|c| *c as u16).chain(values.iter().cloned()) {
            let b = chk >> 20;
            chk = ((chk & 0xFFFFF) << 10) ^ (v as u32);
            for i in 0..10 {
                if (b >> i) & 1 != 0 {
                    chk ^= GEN[i as usize];
                }
            }
        }
        chk
    }
}

#[cfg(test)]
mod test {
    use super::{ShamirSecretSharing, Share, WORDS};
    use std::collections::HashSet;
    use serde_json::Value;
    use rand::{thread_rng, Rng};

    #[test]
    pub fn test_encoding() {
        let m = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
        let sss = Share::from_mnemonic(m).unwrap();
        assert_eq!(sss.to_mnemonic().as_str(), m);
        assert_eq!(ShamirSecretSharing::combine(&[sss], Some("TREZOR")).unwrap(), hex::decode("bb54aac4b89dc868ba37d9cc21b2cece").unwrap());
        let m =  "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney";
        assert!(Share::from_mnemonic(m).is_err());
    }

    #[test]
    pub fn round_trips () {
        let mut secret = [0u8; 32];
        thread_rng().fill(&mut secret);
        for n in 1..16 {
            let shares = ShamirSecretSharing::generate(1, &[(n,n)], &secret[..], None, 0).unwrap();
            assert_eq!(&secret[..], ShamirSecretSharing::combine(&shares, None).unwrap().as_slice());
        }

        for n in 2..5 {
            let shares = ShamirSecretSharing::generate(n, vec![(1,1);n as usize].as_slice(), &secret[..], None, 0).unwrap();
            assert_eq!(&secret[..], ShamirSecretSharing::combine(&shares, None).unwrap().as_slice());
        }

        for n in 3..6 {
            for m in 2..4 {
                let shares = ShamirSecretSharing::generate(1, vec![(m, n)].as_slice(), &secret[..], None, 0).unwrap();
                assert_eq!(&secret[..], ShamirSecretSharing::combine(&shares[.. (m as usize)], None).unwrap().as_slice());
            }
        }
    }

    #[test]
    pub fn precompute () {
        let mut exp = Vec::new();
        let mut log = vec!(0u8; 256);
        let mut poly = 1u16;
        for i in 0u8 .. 255u8 {
            exp.push(poly as u8);
            log[poly as usize] = i;
            poly = (poly << 1) ^ poly;
            if poly & 0x100 != 0 {
                poly ^= 0x11b;
            }
        }

        for (i, e) in exp.iter().enumerate() {
            assert_eq!(ShamirSecretSharing::EXP[i], *e);
        }

        for (i, l) in log.iter().enumerate() {
            assert_eq!(ShamirSecretSharing::LOG[i], *l);
        }
    }

    #[test]
    pub fn wordlist_checks () {
        let mut words = WORDS.clone();
        words.sort();
        assert_eq!(&words[..], &WORDS[..]);
        assert!(!WORDS.iter().any(|w| w.len() < 4 || w.len() > 8));
        let mut first4 = HashSet::new();
        assert!(!WORDS.iter().any(|w| first4.insert(w[..4].to_string()) == false));
    }

    #[test]
    pub fn trezor_tests () {
        let json :Value = serde_json::from_str(TEST_CASES).unwrap();
        let tests = json.as_array().unwrap();
        for t in 0 .. tests.len() {
            let values = tests[t].as_array().unwrap();
            let title = values[0].as_str().unwrap();
            println!("{}", title);
            let result = values[2].as_str().unwrap();
            if result.is_empty() {
                let shares = values[1].as_array().unwrap().iter()
                    .filter_map(|v|
                        if let Ok(s) = Share::from_mnemonic(v.as_str().unwrap()) { Some(s) } else { None }).collect::<Vec<_>>();
                if !shares.is_empty() {
                    assert!(ShamirSecretSharing::combine(&shares, Some("TREZOR")).is_err());
                }
            } else {
                let shares = values[1].as_array().unwrap().iter().map(|v| Share::from_mnemonic(v.as_str().unwrap()).unwrap()).collect::<Vec<_>>();
                assert_eq!(result, hex::encode(ShamirSecretSharing::combine(&shares, Some("TREZOR")).unwrap()));
            }
        }
    }

    const TEST_CASES: &str = r#"
    [
  [
    "1. Valid mnemonic without sharing (128 bits)",
    [
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
    ],
    "bb54aac4b89dc868ba37d9cc21b2cece"
  ],
  [
    "2. Mnemonic with invalid checksum (128 bits)",
    [
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
    ],
    ""
  ],
  [
    "3. Mnemonic with invalid padding (128 bits)",
    [
      "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
    ],
    ""
  ],
  [
    "4. Basic sharing 2-of-3 (128 bits)",
    [
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
      "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking"
    ],
    "b43ceb7e57a0ea8766221624d01b0864"
  ],
  [
    "5. Basic sharing 2-of-3 (128 bits)",
    [
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed"
    ],
    ""
  ],
  [
    "6. Mnemonics with different identifiers (128 bits)",
    [
      "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
      "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner"
    ],
    ""
  ],
  [
    "7. Mnemonics with different iteration exponents (128 bits)",
    [
      "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
      "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice"
    ],
    ""
  ],
  [
    "8. Mnemonics with mismatching group thresholds (128 bits)",
    [
      "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
      "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
      "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo"
    ],
    ""
  ],
  [
    "9. Mnemonics with mismatching group counts (128 bits)",
    [
      "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide",
      "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster"
    ],
    ""
  ],
  [
    "10. Mnemonics with greater group threshold than group counts (128 bits)",
    [
      "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
      "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
      "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce"
    ],
    ""
  ],
  [
    "11. Mnemonics with duplicate member indices (128 bits)",
    [
      "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
      "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps"
    ],
    ""
  ],
  [
    "12. Mnemonics with mismatching member thresholds (128 bits)",
    [
      "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
      "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo"
    ],
    ""
  ],
  [
    "13. Mnemonics giving an invalid digest (128 bits)",
    [
      "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
      "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition"
    ],
    ""
  ],
  [
    "14. Insufficient number of groups (128 bits, case 1)",
    [
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
    ],
    ""
  ],
  [
    "15. Insufficient number of groups (128 bits, case 2)",
    [
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter"
    ],
    ""
  ],
  [
    "16. Threshold number of groups, but insufficient number of members in one group (128 bits)",
    [
      "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
    ],
    ""
  ],
  [
    "17. Threshold number of groups and members in each group (128 bits, case 1)",
    [
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
      "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
      "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
      "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
    ],
    "7c3397a292a5941682d7a4ae2d898d11"
  ],
  [
    "18. Threshold number of groups and members in each group (128 bits, case 2)",
    [
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join"
    ],
    "7c3397a292a5941682d7a4ae2d898d11"
  ],
  [
    "19. Threshold number of groups and members in each group (128 bits, case 3)",
    [
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market"
    ],
    "7c3397a292a5941682d7a4ae2d898d11"
  ],
  [
    "20. Valid mnemonic without sharing (256 bits)",
    [
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck"
    ],
    "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92"
  ],
  [
    "21. Mnemonic with invalid checksum (256 bits)",
    [
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
    ],
    ""
  ],
  [
    "22. Mnemonic with invalid padding (256 bits)",
    [
      "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister"
    ],
    ""
  ],
  [
    "23. Basic sharing 2-of-3 (256 bits)",
    [
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
      "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade"
    ],
    "c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae"
  ],
  [
    "24. Basic sharing 2-of-3 (256 bits)",
    [
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap"
    ],
    ""
  ],
  [
    "25. Mnemonics with different identifiers (256 bits)",
    [
      "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
      "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule"
    ],
    ""
  ],
  [
    "26. Mnemonics with different iteration exponents (256 bits)",
    [
      "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
      "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk"
    ],
    ""
  ],
  [
    "27. Mnemonics with mismatching group thresholds (256 bits)",
    [
      "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
      "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
      "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger"
    ],
    ""
  ],
  [
    "28. Mnemonics with mismatching group counts (256 bits)",
    [
      "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
      "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart"
    ],
    ""
  ],
  [
    "29. Mnemonics with greater group threshold than group counts (256 bits)",
    [
      "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
      "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
      "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful"
    ],
    ""
  ],
  [
    "30. Mnemonics with duplicate member indices (256 bits)",
    [
      "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
      "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart"
    ],
    ""
  ],
  [
    "31. Mnemonics with mismatching member thresholds (256 bits)",
    [
      "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
      "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate"
    ],
    ""
  ],
  [
    "32. Mnemonics giving an invalid digest (256 bits)",
    [
      "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
      "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission"
    ],
    ""
  ],
  [
    "33. Insufficient number of groups (256 bits, case 1)",
    [
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
    ],
    ""
  ],
  [
    "34. Insufficient number of groups (256 bits, case 2)",
    [
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
    ],
    ""
  ],
  [
    "35. Threshold number of groups, but insufficient number of members in one group (256 bits)",
    [
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
    ],
    ""
  ],
  [
    "36. Threshold number of groups and members in each group (256 bits, case 1)",
    [
      "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
      "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club"
    ],
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
  ],
  [
    "37. Threshold number of groups and members in each group (256 bits, case 2)",
    [
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
    ],
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
  ],
  [
    "38. Threshold number of groups and members in each group (256 bits, case 3)",
    [
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs"
    ],
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
  ],
  [
    "39. Mnemonic with insufficient length",
    [
      "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
    ],
    ""
  ],
  [
    "40. Mnemonic with invalid master secret length",
    [
      "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter"
    ],
    ""
  ]
]
    "#;
}

const WORDS: [&str; RADIX] = [
"academic",
"acid",
"acne",
"acquire",
"acrobat",
"activity",
"actress",
"adapt",
"adequate",
"adjust",
"admit",
"adorn",
"adult",
"advance",
"advocate",
"afraid",
"again",
"agency",
"agree",
"aide",
"aircraft",
"airline",
"airport",
"ajar",
"alarm",
"album",
"alcohol",
"alien",
"alive",
"alpha",
"already",
"alto",
"aluminum",
"always",
"amazing",
"ambition",
"amount",
"amuse",
"analysis",
"anatomy",
"ancestor",
"ancient",
"angel",
"angry",
"animal",
"answer",
"antenna",
"anxiety",
"apart",
"aquatic",
"arcade",
"arena",
"argue",
"armed",
"artist",
"artwork",
"aspect",
"auction",
"august",
"aunt",
"average",
"aviation",
"avoid",
"award",
"away",
"axis",
"axle",
"beam",
"beard",
"beaver",
"become",
"bedroom",
"behavior",
"being",
"believe",
"belong",
"benefit",
"best",
"beyond",
"bike",
"biology",
"birthday",
"bishop",
"black",
"blanket",
"blessing",
"blimp",
"blind",
"blue",
"body",
"bolt",
"boring",
"born",
"both",
"boundary",
"bracelet",
"branch",
"brave",
"breathe",
"briefing",
"broken",
"brother",
"browser",
"bucket",
"budget",
"building",
"bulb",
"bulge",
"bumpy",
"bundle",
"burden",
"burning",
"busy",
"buyer",
"cage",
"calcium",
"camera",
"campus",
"canyon",
"capacity",
"capital",
"capture",
"carbon",
"cards",
"careful",
"cargo",
"carpet",
"carve",
"category",
"cause",
"ceiling",
"center",
"ceramic",
"champion",
"change",
"charity",
"check",
"chemical",
"chest",
"chew",
"chubby",
"cinema",
"civil",
"class",
"clay",
"cleanup",
"client",
"climate",
"clinic",
"clock",
"clogs",
"closet",
"clothes",
"club",
"cluster",
"coal",
"coastal",
"coding",
"column",
"company",
"corner",
"costume",
"counter",
"course",
"cover",
"cowboy",
"cradle",
"craft",
"crazy",
"credit",
"cricket",
"criminal",
"crisis",
"critical",
"crowd",
"crucial",
"crunch",
"crush",
"crystal",
"cubic",
"cultural",
"curious",
"curly",
"custody",
"cylinder",
"daisy",
"damage",
"dance",
"darkness",
"database",
"daughter",
"deadline",
"deal",
"debris",
"debut",
"decent",
"decision",
"declare",
"decorate",
"decrease",
"deliver",
"demand",
"density",
"deny",
"depart",
"depend",
"depict",
"deploy",
"describe",
"desert",
"desire",
"desktop",
"destroy",
"detailed",
"detect",
"device",
"devote",
"diagnose",
"dictate",
"diet",
"dilemma",
"diminish",
"dining",
"diploma",
"disaster",
"discuss",
"disease",
"dish",
"dismiss",
"display",
"distance",
"dive",
"divorce",
"document",
"domain",
"domestic",
"dominant",
"dough",
"downtown",
"dragon",
"dramatic",
"dream",
"dress",
"drift",
"drink",
"drove",
"drug",
"dryer",
"duckling",
"duke",
"duration",
"dwarf",
"dynamic",
"early",
"earth",
"easel",
"easy",
"echo",
"eclipse",
"ecology",
"edge",
"editor",
"educate",
"either",
"elbow",
"elder",
"election",
"elegant",
"element",
"elephant",
"elevator",
"elite",
"else",
"email",
"emerald",
"emission",
"emperor",
"emphasis",
"employer",
"empty",
"ending",
"endless",
"endorse",
"enemy",
"energy",
"enforce",
"engage",
"enjoy",
"enlarge",
"entrance",
"envelope",
"envy",
"epidemic",
"episode",
"equation",
"equip",
"eraser",
"erode",
"escape",
"estate",
"estimate",
"evaluate",
"evening",
"evidence",
"evil",
"evoke",
"exact",
"example",
"exceed",
"exchange",
"exclude",
"excuse",
"execute",
"exercise",
"exhaust",
"exotic",
"expand",
"expect",
"explain",
"express",
"extend",
"extra",
"eyebrow",
"facility",
"fact",
"failure",
"faint",
"fake",
"false",
"family",
"famous",
"fancy",
"fangs",
"fantasy",
"fatal",
"fatigue",
"favorite",
"fawn",
"fiber",
"fiction",
"filter",
"finance",
"findings",
"finger",
"firefly",
"firm",
"fiscal",
"fishing",
"fitness",
"flame",
"flash",
"flavor",
"flea",
"flexible",
"flip",
"float",
"floral",
"fluff",
"focus",
"forbid",
"force",
"forecast",
"forget",
"formal",
"fortune",
"forward",
"founder",
"fraction",
"fragment",
"frequent",
"freshman",
"friar",
"fridge",
"friendly",
"frost",
"froth",
"frozen",
"fumes",
"funding",
"furl",
"fused",
"galaxy",
"game",
"garbage",
"garden",
"garlic",
"gasoline",
"gather",
"general",
"genius",
"genre",
"genuine",
"geology",
"gesture",
"glad",
"glance",
"glasses",
"glen",
"glimpse",
"goat",
"golden",
"graduate",
"grant",
"grasp",
"gravity",
"gray",
"greatest",
"grief",
"grill",
"grin",
"grocery",
"gross",
"group",
"grownup",
"grumpy",
"guard",
"guest",
"guilt",
"guitar",
"gums",
"hairy",
"hamster",
"hand",
"hanger",
"harvest",
"have",
"havoc",
"hawk",
"hazard",
"headset",
"health",
"hearing",
"heat",
"helpful",
"herald",
"herd",
"hesitate",
"hobo",
"holiday",
"holy",
"home",
"hormone",
"hospital",
"hour",
"huge",
"human",
"humidity",
"hunting",
"husband",
"hush",
"husky",
"hybrid",
"idea",
"identify",
"idle",
"image",
"impact",
"imply",
"improve",
"impulse",
"include",
"income",
"increase",
"index",
"indicate",
"industry",
"infant",
"inform",
"inherit",
"injury",
"inmate",
"insect",
"inside",
"install",
"intend",
"intimate",
"invasion",
"involve",
"iris",
"island",
"isolate",
"item",
"ivory",
"jacket",
"jerky",
"jewelry",
"join",
"judicial",
"juice",
"jump",
"junction",
"junior",
"junk",
"jury",
"justice",
"kernel",
"keyboard",
"kidney",
"kind",
"kitchen",
"knife",
"knit",
"laden",
"ladle",
"ladybug",
"lair",
"lamp",
"language",
"large",
"laser",
"laundry",
"lawsuit",
"leader",
"leaf",
"learn",
"leaves",
"lecture",
"legal",
"legend",
"legs",
"lend",
"length",
"level",
"liberty",
"library",
"license",
"lift",
"likely",
"lilac",
"lily",
"lips",
"liquid",
"listen",
"literary",
"living",
"lizard",
"loan",
"lobe",
"location",
"losing",
"loud",
"loyalty",
"luck",
"lunar",
"lunch",
"lungs",
"luxury",
"lying",
"lyrics",
"machine",
"magazine",
"maiden",
"mailman",
"main",
"makeup",
"making",
"mama",
"manager",
"mandate",
"mansion",
"manual",
"marathon",
"march",
"market",
"marvel",
"mason",
"material",
"math",
"maximum",
"mayor",
"meaning",
"medal",
"medical",
"member",
"memory",
"mental",
"merchant",
"merit",
"method",
"metric",
"midst",
"mild",
"military",
"mineral",
"minister",
"miracle",
"mixed",
"mixture",
"mobile",
"modern",
"modify",
"moisture",
"moment",
"morning",
"mortgage",
"mother",
"mountain",
"mouse",
"move",
"much",
"mule",
"multiple",
"muscle",
"museum",
"music",
"mustang",
"nail",
"national",
"necklace",
"negative",
"nervous",
"network",
"news",
"nuclear",
"numb",
"numerous",
"nylon",
"oasis",
"obesity",
"object",
"observe",
"obtain",
"ocean",
"often",
"olympic",
"omit",
"oral",
"orange",
"orbit",
"order",
"ordinary",
"organize",
"ounce",
"oven",
"overall",
"owner",
"paces",
"pacific",
"package",
"paid",
"painting",
"pajamas",
"pancake",
"pants",
"papa",
"paper",
"parcel",
"parking",
"party",
"patent",
"patrol",
"payment",
"payroll",
"peaceful",
"peanut",
"peasant",
"pecan",
"penalty",
"pencil",
"percent",
"perfect",
"permit",
"petition",
"phantom",
"pharmacy",
"photo",
"phrase",
"physics",
"pickup",
"picture",
"piece",
"pile",
"pink",
"pipeline",
"pistol",
"pitch",
"plains",
"plan",
"plastic",
"platform",
"playoff",
"pleasure",
"plot",
"plunge",
"practice",
"prayer",
"preach",
"predator",
"pregnant",
"premium",
"prepare",
"presence",
"prevent",
"priest",
"primary",
"priority",
"prisoner",
"privacy",
"prize",
"problem",
"process",
"profile",
"program",
"promise",
"prospect",
"provide",
"prune",
"public",
"pulse",
"pumps",
"punish",
"puny",
"pupal",
"purchase",
"purple",
"python",
"quantity",
"quarter",
"quick",
"quiet",
"race",
"racism",
"radar",
"railroad",
"rainbow",
"raisin",
"random",
"ranked",
"rapids",
"raspy",
"reaction",
"realize",
"rebound",
"rebuild",
"recall",
"receiver",
"recover",
"regret",
"regular",
"reject",
"relate",
"remember",
"remind",
"remove",
"render",
"repair",
"repeat",
"replace",
"require",
"rescue",
"research",
"resident",
"response",
"result",
"retailer",
"retreat",
"reunion",
"revenue",
"review",
"reward",
"rhyme",
"rhythm",
"rich",
"rival",
"river",
"robin",
"rocky",
"romantic",
"romp",
"roster",
"round",
"royal",
"ruin",
"ruler",
"rumor",
"sack",
"safari",
"salary",
"salon",
"salt",
"satisfy",
"satoshi",
"saver",
"says",
"scandal",
"scared",
"scatter",
"scene",
"scholar",
"science",
"scout",
"scramble",
"screw",
"script",
"scroll",
"seafood",
"season",
"secret",
"security",
"segment",
"senior",
"shadow",
"shaft",
"shame",
"shaped",
"sharp",
"shelter",
"sheriff",
"short",
"should",
"shrimp",
"sidewalk",
"silent",
"silver",
"similar",
"simple",
"single",
"sister",
"skin",
"skunk",
"slap",
"slavery",
"sled",
"slice",
"slim",
"slow",
"slush",
"smart",
"smear",
"smell",
"smirk",
"smith",
"smoking",
"smug",
"snake",
"snapshot",
"sniff",
"society",
"software",
"soldier",
"solution",
"soul",
"source",
"space",
"spark",
"speak",
"species",
"spelling",
"spend",
"spew",
"spider",
"spill",
"spine",
"spirit",
"spit",
"spray",
"sprinkle",
"square",
"squeeze",
"stadium",
"staff",
"standard",
"starting",
"station",
"stay",
"steady",
"step",
"stick",
"stilt",
"story",
"strategy",
"strike",
"style",
"subject",
"submit",
"sugar",
"suitable",
"sunlight",
"superior",
"surface",
"surprise",
"survive",
"sweater",
"swimming",
"swing",
"switch",
"symbolic",
"sympathy",
"syndrome",
"system",
"tackle",
"tactics",
"tadpole",
"talent",
"task",
"taste",
"taught",
"taxi",
"teacher",
"teammate",
"teaspoon",
"temple",
"tenant",
"tendency",
"tension",
"terminal",
"testify",
"texture",
"thank",
"that",
"theater",
"theory",
"therapy",
"thorn",
"threaten",
"thumb",
"thunder",
"ticket",
"tidy",
"timber",
"timely",
"ting",
"tofu",
"together",
"tolerate",
"total",
"toxic",
"tracks",
"traffic",
"training",
"transfer",
"trash",
"traveler",
"treat",
"trend",
"trial",
"tricycle",
"trip",
"triumph",
"trouble",
"true",
"trust",
"twice",
"twin",
"type",
"typical",
"ugly",
"ultimate",
"umbrella",
"uncover",
"undergo",
"unfair",
"unfold",
"unhappy",
"union",
"universe",
"unkind",
"unknown",
"unusual",
"unwrap",
"upgrade",
"upstairs",
"username",
"usher",
"usual",
"valid",
"valuable",
"vampire",
"vanish",
"various",
"vegan",
"velvet",
"venture",
"verdict",
"verify",
"very",
"veteran",
"vexed",
"victim",
"video",
"view",
"vintage",
"violence",
"viral",
"visitor",
"visual",
"vitamins",
"vocal",
"voice",
"volume",
"voter",
"voting",
"walnut",
"warmth",
"warn",
"watch",
"wavy",
"wealthy",
"weapon",
"webcam",
"welcome",
"welfare",
"western",
"width",
"wildlife",
"window",
"wine",
"wireless",
"wisdom",
"withdraw",
"wits",
"wolf",
"woman",
"work",
"worthy",
"wrap",
"wrist",
"writing",
"wrote",
"year",
"yelp",
"yield",
"yoga",
"zero"
];
