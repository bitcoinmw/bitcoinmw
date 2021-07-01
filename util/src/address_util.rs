// Copyright 2021 The BitcoinMW Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// some address utilities

use bech32::u5;
use bech32::WriteBase32;
use bitcoin_hashes::sha256d;
use bitcoin_hashes::Hash;
use failure::{Context, Fail};
use rust_base58::ToBase58;
use std::borrow::Cow;
use std::fmt;

/// Case enum
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Case {
	/// Upper case
	Upper,
	/// Lower case
	Lower,
	/// No case
	None,
}

/// Errors that occur in address utils
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

/// Kinds of errors for the utxo mod
#[derive(Debug, Fail)]
pub enum ErrorKind {
	/// File not found
	#[fail(display = "File not found: '{}'", _0)]
	FileNotFound(String),
	/// Invalid Length
	#[fail(display = "Invalid Length")]
	InvalidLength,
	/// Mixed Case
	#[fail(display = "Mixed case not allowed")]
	MixedCase,
	/// Invalid char
	#[fail(display = "Invalid char: '{}'", _0)]
	InvalidChar(char),
	/// Unknown Address Type
	#[fail(display = "Unknown Address Type")]
	UnknownAddressType,
	/// Address not found
	#[fail(display = "Address not found")]
	AddressNotFound,
	/// IndexOutOfBounds
	#[fail(display = "Index Out of Bounds")]
	IndexOutOfBounds,
	/// IO Error
	#[fail(display = "IO Error: {}", _0)]
	IOError(String),
	/// Bech32 error
	#[fail(display = "Bech32 Error: {}", _0)]
	Bech32Error(String),
	/// Format error
	#[fail(display = "Format Error: {}", _0)]
	FormatError(String),
	/// Encoding error
	#[fail(display = "Encoding Error: {}", _0)]
	EncodingError(String),
	/// UtxoData not loaded
	#[fail(display = "Utxo Data not loaded")]
	NotLoaded,
	/// Invalid Peer
	#[fail(display = "Invalid peer: {}", _0)]
	InvalidPeer(String),
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IOError(error.to_string())),
		}
	}
}

impl From<bech32::Error> for Error {
	fn from(error: bech32::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Bech32Error(error.to_string())),
		}
	}
}

impl From<failure::Error> for Error {
	fn from(error: failure::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::EncodingError(error.to_string())),
		}
	}
}

/// Get an address as string based on the u8 input vector
pub fn get_address(byte_data: Vec<u8>) -> Result<String, Error> {
	let byte_data = &byte_data[..21];
	let checksum = sha256d::Hash::hash(&byte_data);
	let mut byte_data = byte_data.to_vec();
	byte_data.append(&mut checksum[0..4].to_vec());
	Ok(byte_data.to_base58())
}

/// Check the human readable part of a bech32 address
pub fn check_hrp(hrp: &str) -> Result<Case, Error> {
	if hrp.is_empty() || hrp.len() > 83 {
		return Err(ErrorKind::InvalidLength.into());
	}

	let mut has_lower: bool = false;
	let mut has_upper: bool = false;
	for b in hrp.bytes() {
		// Valid subset of ASCII
		if b < 33 || b > 126 {
			return Err(ErrorKind::InvalidChar(b as char).into());
		}

		if b >= b'a' && b <= b'z' {
			has_lower = true;
		} else if b >= b'A' && b <= b'Z' {
			has_upper = true;
		};

		if has_lower && has_upper {
			return Err(ErrorKind::MixedCase.into());
		}
	}
	Ok(match (has_upper, has_lower) {
		(true, false) => Case::Upper,
		(false, true) => Case::Lower,
		(false, false) => Case::None,
		(true, true) => unreachable!(),
	})
}

/// Encode a bech32 address
pub fn encode_to_fmt(
	fmt: &mut dyn fmt::Write,
	hrp: &str,
	data: Vec<u5>,
) -> Result<fmt::Result, Error> {
	let data = &data[..];
	let hrp_lower = match check_hrp(&hrp)? {
		Case::Upper => Cow::Owned(hrp.to_lowercase()),
		Case::Lower | Case::None => Cow::Borrowed(hrp),
	};

	match bech32::Bech32Writer::new(&hrp_lower, fmt) {
		Ok(mut writer) => {
			Ok(writer.write(data.as_ref()).and_then(|_| {
				// Finalize manually to avoid panic on drop if write fails
				writer.finalize()
			}))
		}
		Err(e) => Ok(Err(e)),
	}
}

/// Encode a bech32 payload to string.
///
/// # Errors
/// * If [check_hrp] returns an error for the given HRP.
/// # Deviations from standard
/// * No length limits are enforced for the data part
pub fn encode(hrp: &str, data: Vec<u5>) -> Result<String, Error> {
	let mut buf = String::new();
	let res = encode_to_fmt(&mut buf, hrp, data)?;
	if res.is_err() {
		Err(ErrorKind::FormatError(format!("{:?}", res)).into())
	} else {
		Ok(buf)
	}
}
