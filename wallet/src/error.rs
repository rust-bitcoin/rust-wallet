//
// Copyright 2018 rust-wallet developers
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
// !
//! # Wallet Error
//!
//! Modules of this library use this error class to indicate problems.
//!

use std::convert;
use std::error::Error;
use std::fmt;
use std::io;
use bitcoin::util::bip32;
use crypto::symmetriccipher;

/// An error class to offer a unified error interface upstream
pub enum WalletError {
    /// Network IO error
    IO(io::Error),
    /// key derivation error
    KeyDerivation(bip32::Error),
    /// cipher error
    SymmetricCipherError(symmetriccipher::SymmetricCipherError),
    /// has no key in db
    HasNoWalletInDatabase,
    /// Mnemonic contains an unknown word
    UnknownMnemonicWord,
    /// Mnemonic must have a word count divisible by 3
    InvalidMnemonicLength,
    /// Data for mnemonic should have a length divisible by 4
    InvalidMnemonicData,
    /// Mnemonic checking bits not match
    MnemonicChecksumNotMatch,
    /// Cannot obtain random source
    CannotObtainRandomSource,
}

impl Error for WalletError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            &WalletError::IO(ref err) => Some(err),
            &WalletError::KeyDerivation(ref err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            &WalletError::IO(ref err) => write!(f, "IO error: {}", err),
            &WalletError::KeyDerivation(ref err) => write!(f, "BIP32 error: {}", err),
            &WalletError::SymmetricCipherError(ref err) => write!(
                f,
                "Cipher error: {}",
                match err {
                    &symmetriccipher::SymmetricCipherError::InvalidLength => "invalid length",
                    &symmetriccipher::SymmetricCipherError::InvalidPadding => "invalid padding",
                }
            ),
            &WalletError::HasNoWalletInDatabase => write!(f, "has no wallet in database"),
            &WalletError::UnknownMnemonicWord => write!(f, "mnemonic contains an unknown word"),
            &WalletError::InvalidMnemonicLength => {
                write!(f, "mnemonic must have a word count divisible by 3")
            },
            &WalletError::InvalidMnemonicData => {
                write!(f, "data for mnemonic should have a length divisible by 4")
            },
            &WalletError::MnemonicChecksumNotMatch => write!(f, "mnemonic checking bits not match"),
            &WalletError::CannotObtainRandomSource => write!(f, "cannot obtain random source"),
        }
    }
}

impl fmt::Debug for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &fmt::Display).fmt(f)
    }
}

impl convert::From<WalletError> for io::Error {
    fn from(err: WalletError) -> io::Error {
        match err {
            WalletError::IO(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, err.description()),
        }
    }
}

impl convert::From<io::Error> for WalletError {
    fn from(err: io::Error) -> WalletError {
        WalletError::IO(err)
    }
}

impl convert::From<bip32::Error> for WalletError {
    fn from(err: bip32::Error) -> WalletError {
        WalletError::KeyDerivation(err)
    }
}

impl convert::From<symmetriccipher::SymmetricCipherError> for WalletError {
    fn from(err: symmetriccipher::SymmetricCipherError) -> WalletError {
        WalletError::SymmetricCipherError(err)
    }
}
