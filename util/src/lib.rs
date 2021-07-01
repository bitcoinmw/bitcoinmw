// Copyright 2020 The Grin Developers
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

//! Logging, as well as various low-level utilities that factor Rust
//! patterns that are frequent within the grin codebase.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;

mod ov3;
pub use ov3::OnionV3Address;
pub use ov3::OnionV3Error as OnionV3AddressError;

// Re-export so only has to be included once
pub use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

// Re-export so only has to be included once
pub use secp256k1zkp as secp;

// Logging related
pub mod logger;
pub use crate::logger::{init_logger, init_test_logger};

// Static secp instance
pub mod secp_static;
pub use crate::secp_static::static_secp_instance;

/// Static hash object
pub mod static_hash;

/// Address utilities
pub mod address_util;

/// PrintUtil
pub mod print_util;

pub mod types;
pub use crate::types::ZeroingString;

pub mod macros;

// other utils
#[allow(unused_imports)]
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
/// hex utils
pub mod hex;
pub use crate::hex::*;

/// File util
pub mod file;
/// Compress and decompress zip bz2 archives
pub mod zip;

mod rate_counter;
pub use crate::rate_counter::RateCounter;

use failure;
extern crate failure_derive;

use crate::failure::Error;
use bech32::u5;
use bech32::FromBase32;
use failure::Fail;
use rust_base58::FromBase58;

/// constants used for address type
/// p2sh address type
pub const P2SH: u8 = 0;
/// p2wsh address type
pub const P2WSH: u8 = 1;
/// p2shwsh address type
pub const P2SHWSH: u8 = 2;
/// p2pkh address type
pub const P2PKH: u8 = 3;
/// p2shwpkh address type
pub const P2SHWPKH: u8 = 4;
/// p2wpkh address type
pub const P2WPKH: u8 = 5;

/// Errors during encoding process
#[derive(Debug, Fail)]
pub enum ErrorKind {
	/// The block doesn't fit anywhere in our chain
	#[fail(display = "Encoding error: {}", _0)]
	EncodingError(String),
}

/// Convert a string to a base58 encoded vec
pub fn from_base58(encoded: &str) -> Result<Vec<u8>, Error> {
	let ret = encoded.from_base58();
	if ret.is_err() {
		Err(ErrorKind::EncodingError(format!("{:?}", ret)).into())
	} else {
		let mut ret = ret.unwrap();
		ret.remove(0);
		Ok(ret)
	}
}

/// Convert a string p2wsh address to a base58 encoded vec
pub fn from_base32_p2wsh(encoded: &str) -> Result<Vec<u8>, Error> {
	let mut padded = [u5::try_from_u8(0)?; 52];
	let (_, data) = bech32::decode(&encoded)?;
	let len = data.len();
	for i in 0..len - 1 {
		padded[i] = data[i + 1];
	}
	let ret = Vec::<u8>::from_base32(&padded)?;
	Ok(ret)
}

/// Convert a string to a base32 encoded vec
pub fn from_base32(encoded: &str) -> Result<Vec<u8>, Error> {
	let mut padded = [u5::try_from_u8(0)?; 32];
	let (_, data) = bech32::decode(&encoded)?;
	let len = data.len();
	for i in 0..len - 1 {
		padded[i] = data[i + 1];
	}
	let mut ret = Vec::<u8>::from_base32(&padded)?;
	ret.append(&mut vec![0 as u8, 0 as u8, 0 as u8, 0 as u8]);
	Ok(ret)
}

/// Convert a string to a bech32 v1plus vec
pub fn from_bech_v1plus(encoded: &str) -> Result<Vec<u8>, Error> {
	let mut padded = [u5::try_from_u8(0)?; 90];
	let (_, data) = bech32::decode(&encoded)?;
	let len = data.len();
	for i in 0..len - 1 {
		padded[i] = data[i + 1];
	}
	let mut ret = Vec::<u8>::from_base32(&padded)?;
	for _ in 0..74 - ret.len() {
		ret.append(&mut vec![0 as u8]);
	}
	// currently only v1/v2 supported
	ret[72] = if encoded.chars().nth(3).unwrap() == 'p' {
		1
	} else {
		// only support v1/v2 for now since that's all that's in the blockchain
		2
	};
	ret[73] = encoded.len() as u8;
	Ok(ret)
}

/// Encode an address from string to Vec
pub fn encode_addr(address: String) -> Result<Vec<u8>, Error> {
	if address.len() > 90 {
		Err(
			ErrorKind::EncodingError(format!("Address too long. Max length is 90. [{}]", address))
				.into(),
		)
	} else if address.starts_with("1") {
		Ok(from_base58(&address)?)
	} else if address.starts_with("3") {
		Ok(from_base58(&address)?)
	} else if address.starts_with("b") && !address.starts_with("bc1q") {
		Ok(from_bech_v1plus(&address)?)
	} else if address.starts_with("b") && address.len() <= 42 {
		Ok(from_base32(&address)?)
	} else if address.starts_with("b") && address.len() <= 62 {
		Ok(from_base32_p2wsh(&address)?)
	} else {
		Err(ErrorKind::EncodingError(format!("Unknown Address type: {}", address)).into())
	}
}

/// Encapsulation of a RwLock<Option<T>> for one-time initialization.
/// This implementation will purposefully fail hard if not used
/// properly, for example if not initialized before being first used
/// (borrowed).
#[derive(Clone)]
pub struct OneTime<T> {
	/// The inner value.
	inner: Arc<RwLock<Option<T>>>,
}

impl<T> OneTime<T>
where
	T: Clone,
{
	/// Builds a new uninitialized OneTime.
	pub fn new() -> OneTime<T> {
		OneTime {
			inner: Arc::new(RwLock::new(None)),
		}
	}

	/// Initializes the OneTime, should only be called once after construction.
	/// Will panic (via assert) if called more than once.
	pub fn init(&self, value: T) {
		let mut inner = self.inner.write();
		assert!(inner.is_none());
		*inner = Some(value);
	}

	/// Borrows the OneTime, should only be called after initialization.
	/// Will panic (via expect) if called before initialization.
	pub fn borrow(&self) -> T {
		let inner = self.inner.read();
		inner
			.clone()
			.expect("Cannot borrow one_time before initialization.")
	}

	/// Has this OneTime been initialized?
	pub fn is_init(&self) -> bool {
		self.inner.read().is_some()
	}
}

/// Encode an utf8 string to a base64 string
pub fn to_base64(s: &str) -> String {
	base64::encode(s)
}

/// Flag used for legacy addresses
pub const FLAG_LEGACY_ADDRESS: u64 = 0x800000000000;
/// Flag used for P2SH addresses
pub const FLAG_P2SH_ADDRESS: u64 = 0x400000000000;
/// Flag used for Bech32 addresses
pub const FLAG_BECH32_ADDRESS: u64 = 0x200000000000;
/// Flag used for Bech32 v1plus address (note, it's a combination of the BECH32 flag and the legacy flag
pub const FLAG_BECH32_V1_PLUS_ADDRESS: u64 = FLAG_BECH32_ADDRESS | FLAG_LEGACY_ADDRESS;
/// Flag used for raw script hashes (note, it's a combination of the legacy flag and the p2sh flag
pub const FLAG_RAW_SCRIPT_HASH: u64 = FLAG_LEGACY_ADDRESS | FLAG_P2SH_ADDRESS;

/// Global stopped/paused state shared across various subcomponents of Grin.
///
/// "Stopped" allows a clean shutdown of the Grin server.
/// "Paused" is used in some tests to allow nodes to reach steady state etc.
///
pub struct StopState {
	stopped: AtomicBool,
	paused: AtomicBool,
}

impl StopState {
	/// Create a new stop_state in default "running" state.
	pub fn new() -> StopState {
		StopState {
			stopped: AtomicBool::new(false),
			paused: AtomicBool::new(false),
		}
	}

	/// Check if we are stopped.
	pub fn is_stopped(&self) -> bool {
		self.stopped.load(Ordering::Relaxed)
	}

	/// Check if we are paused.
	pub fn is_paused(&self) -> bool {
		self.paused.load(Ordering::Relaxed)
	}

	/// Stop the server.
	pub fn stop(&self) {
		self.stopped.store(true, Ordering::Relaxed)
	}

	/// Pause the server (only used in tests).
	pub fn pause(&self) {
		self.paused.store(true, Ordering::Relaxed)
	}

	/// Resume a paused server (only used in tests).
	pub fn resume(&self) {
		self.paused.store(false, Ordering::Relaxed)
	}
}
