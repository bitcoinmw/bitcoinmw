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

// Errors for the utxo crate.

use failure::{Context, Fail};

/// Error definition
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

impl From<grin_util::address_util::Error> for Error {
	fn from(error: grin_util::address_util::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::EncodingError(format!("{:?}", error))),
		}
	}
}
