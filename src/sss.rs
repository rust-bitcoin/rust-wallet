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
use std::ops::Range;
use rand::{thread_rng, RngCore};
use crypto::mac::Mac;
use bitcoin::bech32::ToBase32;
use std::collections::HashSet;

pub struct ShamirSecretSharing {
}

impl ShamirSecretSharing {
    pub fn generate (group_treshold: u8, groups: &[(u8, u8)], secret: Vec<u8>, passphrase: Option<&str>, iteration_exponent: u8) -> Result<Vec<Share>, Error> {
        if secret.len() < 16 || secret.len() % 2 != 0 {
            return Err(Error::Unsupported("master key entropy must be at least 128 bits and multiple of 16 bits"));
        }
        Ok(Vec::new())
    }

    fn recover_secret(threshold: u8, shares: &Vec<(u8, Vec<u8>)>) -> Result<Vec<u8>, Error> {
        if threshold == 1 {
            return Ok(shares[0].1.clone());
        }
        let shared_secret = Self::interpolate(shares, 255)?;
        let digest_share = Self::interpolate(shares, 254)?;
        if &digest_share[..4] != Self::share_digest(&digest_share[4..], shared_secret.as_slice()).as_slice() {
            return Err(Error::Unsupported("share digest incorrect"));
        }
        Ok(shared_secret)
    }

    fn split_secret (threshold: u8, share_count: u8, shared_secret: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Error> {
        if threshold < 1 {
            return Err(Error::Unsupported("sharing threashold must be > 1"));
        }

        if threshold > share_count {
            return Err(Error::Unsupported("number of shares should be at least equal threshold"));
        }

        if share_count > 16 {
            return Err(Error::Unsupported("more than 16 shares are not supported"));
        }

        let mut shares = Vec::new();

        if threshold == 1 {
            for i in 0 .. share_count {
                shares.push((i, shared_secret.to_vec()));
            }
            return Ok(shares);
        }

        let random_shares_count = share_count - 2;

        for i in 0 .. random_shares_count {
            let mut share = vec!(0u8; shared_secret.len());
            thread_rng().fill_bytes(share.as_mut_slice());
            shares.push((i, share));
        }


        let mut base_shares = shares.clone();
        let mut random_part = vec!(0u8; shared_secret.len() - 4);
        thread_rng().fill_bytes(random_part.as_mut_slice());
        let mut digest = Self::share_digest(random_part.as_slice(), shared_secret);
        digest.extend_from_slice(random_part.as_slice());
        base_shares.push((254, digest));
        base_shares.push((255, shared_secret.to_vec()));

        for i in random_shares_count .. share_count {
            shares.push((i, Self::interpolate(&base_shares, i)?));
        }

        Ok(shares)
    }

    fn interpolate(shares: &Vec<(u8, Vec<u8>)>, x: u8) -> Result<Vec<u8>, Error> {
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
            return Ok(shares.iter().find_map(|(i, v)| if *i == x {Some (v)} else {None}).unwrap().clone())
        }
        let log_prod = shares.iter().map(|(i, _)| Self::LOG[(*i ^ x) as usize]).fold(0u16, |a, v| a + v as u16);
        let mut result = vec!(0u8; len);
        for (i, share) in shares {
            let log_basis = (
                (log_prod
                - Self::LOG[(*i ^ x) as usize] as u16
                - shares.iter().map(|(j, _)| Self::LOG[(*j ^ *i) as usize]).fold(0u16, |a, v| a + v as u16)
                ) % 255
            ) as u8;
            result.iter_mut().zip(share.iter())
                .for_each(|(r, s)|
                    *r ^= if *s != 0 {
                        Self::EXP[((Self::LOG[*s as usize] + log_basis) % 255) as usize]
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
        Ok(Self::crypt(id, iteration_exponent, master, &[0, 1, 2, 3], passphrase.unwrap_or("")))
    }

    // decrypt master with a passphrase
    fn decrypt(id: u16, iteration_exponent: u8, master: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, Error> {
        Self::checkpass(passphrase)?;
        Ok(Self::crypt(id, iteration_exponent, master, &[3, 2, 1, 0], passphrase.unwrap_or("")))
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
        pbkdf2(&mut mac, salt.as_slice(), 2500u32 << (iteration_exponent as u32), output);
    }

    const EXP:[u8;255] = [1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, ];
    const LOG:[u8;256] = [0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7, ];
}

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
        if words.len() < 20 {
            return Err(Error::Mnemonic("key share mnemonic must be at least 20 words"));
        }
        let padding_len = 10*(words.len() - 4)%16;
        if padding_len > 8 {
            return Err(Error::Unsupported("Invalid mnemonic length"));
        }
        if Self::checksum(words.as_slice()) != 1 {
            return Err(Error::Mnemonic("checksum failed"));
        }
        let value = Self::words_to_bytes(&words[4 .. words.len()-3]);
        let prefix = Self::words_to_bytes(&words[..4]);
        let mut cursor = Cursor::new(&prefix);
        let mut reader = BitStreamReader::new(&mut cursor);
        Ok(Share {
            id: reader.read(15).unwrap() as u16,
            iteration_exponent: reader.read(5).unwrap() as u8,
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
        bytes.extend_from_slice(self.value.as_slice());
        let mut words = Self::bytes_to_words(&bytes[..]);
        words.push(0);
        words.push(0);
        words.push(0);
        let chk = Self::checksum(words.as_slice()) ^ 1;
        let len = words.len();
        for i in 0..3 {
            words[len - 3 + i] = ((chk >> (10 * (2 - i as u32))) & 1023) as u16;
        }
        Self::words_to_mnemonic(&words[..])
    }

    // convert from byte vector to a vector of 10 bit words
    fn bytes_to_words (bytes: &[u8]) -> Vec<u16> {
        let mut words = Vec::new();
        let mut cursor = Cursor::new(bytes);
        let mut reader = BitStreamReader::new(&mut cursor);
        while let Ok(w) = reader.read(10) {
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

        const SALT :[u16;6] = ['s' as u16, 'h' as u16, 'a' as u16, 'm' as u16, 'i' as u16, 'r' as u16];

        let mut chk = 1u32;
        for v in SALT.iter().chain(values.iter()) {
            let b = chk >> 20;
            chk = ((chk & 0xFFFFF) << 10) ^ (*v as u32);
            for i in 0..10 {
                if (b >> i) & 1 != 0 {
                    chk ^= GEN[i as usize];
                }
            }
        }
        chk
    }
}

mod test {
    use super::{ShamirSecretSharing, Share};
    use sss::WORDS;
    use std::collections::HashSet;

    #[test]
    pub fn test_encoding() {
        let m = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
        let sss = Share::from_mnemonic(m).unwrap();
        assert_eq!(sss.to_mnemonic().as_str(), m);
        let m =  "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney";
        assert!(Share::from_mnemonic(m).is_err());
        let m = "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness";
        assert!(Share::from_mnemonic(m).is_err());
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
}

const WORDS: [&str; 1024] = [
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
