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

//! Transactions

use crate::core::hash::{DefaultHashable, Hash, Hashed};
use crate::core::verifier_cache::VerifierCache;
use crate::core::{committed, Committed};
use crate::libtx::{aggsig, secp_ser};
use crate::ser::{
	self, read_multi, PMMRable, Readable, Reader, VerifySortedAndUnique, Writeable, Writer,
};
use crate::{consensus, global};
use bitcoin::secp256k1::recovery::RecoveryId;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::key::PublicKey as BitcoinPublicKey;
use bitcoin::util::misc;
use bitcoin::{Address, Script};
use std::collections::HashMap;

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Instruction::Op;
use bitcoin::blockdata::script::Instruction::PushBytes;
use bitcoin::network::constants::Network::Bitcoin;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::Signature;
use bmw_utxo::utxo_data::UtxoData;
use byte_tools::copy;
use enum_primitive::FromPrimitive;
use keychain::{self, BlindingFactor};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::cmp::{max, min};
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::sync::{Arc, Weak};
use std::{error, fmt};
use util::secp;
use util::secp::key::PublicKey;
use util::secp::pedersen::{Commitment, RangeProof};
use util::secp::ContextFlag;
use util::secp::Signature as SecpSignature;
use util::static_secp_instance;
use util::RwLock;
use util::ToHex;
use util::P2SH;
use util::P2SHWSH;
use util::P2WSH;

/// Fee fields as in fix-fees RFC: { future_use: 20, fee_shift: 4, fee: 40 }
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeeFields(u64);

impl DefaultHashable for FeeFields {}

impl Writeable for FeeFields {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.0)
	}
}

impl Readable for FeeFields {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let fee_fields = reader.read_u64()?;
		Ok(Self(fee_fields))
	}
}

impl Display for FeeFields {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl Serialize for FeeFields {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.collect_str(&self.0)
	}
}

impl<'de> Deserialize<'de> for FeeFields {
	fn deserialize<D>(deserializer: D) -> Result<FeeFields, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct FeeFieldsVisitor;
		impl<'de> de::Visitor<'de> for FeeFieldsVisitor {
			type Value = FeeFields;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("an 64-bit integer")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				let value = value
					.parse()
					.map_err(|_| E::custom(format!("invalid fee field")))?;
				self.visit_u64(value)
			}

			fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				Ok(FeeFields(value))
			}
		}

		deserializer.deserialize_any(FeeFieldsVisitor)
	}
}

/// Conversion from a valid fee to a FeeFields with 0 fee_shift
/// The valid fee range is 1..FEE_MASK
impl TryFrom<u64> for FeeFields {
	type Error = Error;

	fn try_from(fee: u64) -> Result<Self, Self::Error> {
		if fee == 0 {
			Err(Error::InvalidFeeFields)
		} else if fee > FeeFields::FEE_MASK {
			Err(Error::InvalidFeeFields)
		} else {
			Ok(Self(fee))
		}
	}
}

/// Conversion from a 32-bit fee to a FeeFields with 0 fee_shift
/// For use exclusively in tests with constant fees
impl From<u32> for FeeFields {
	fn from(fee: u32) -> Self {
		Self(fee as u64)
	}
}

impl From<FeeFields> for u64 {
	fn from(fee_fields: FeeFields) -> Self {
		fee_fields.0 as u64
	}
}

impl FeeFields {
	/// Fees are limited to 40 bits
	const FEE_BITS: u32 = 40;
	/// Used to extract fee field
	const FEE_MASK: u64 = (1u64 << FeeFields::FEE_BITS) - 1;

	/// Fee shifts are limited to 4 bits
	pub const FEE_SHIFT_BITS: u32 = 4;
	/// Used to extract fee_shift field
	pub const FEE_SHIFT_MASK: u64 = (1u64 << FeeFields::FEE_SHIFT_BITS) - 1;

	/// Create a zero FeeFields with 0 fee and 0 fee_shift
	pub fn zero() -> Self {
		Self(0)
	}

	/// Create a new FeeFields from the provided shift and fee
	/// Checks both are valid (in range)
	pub fn new(fee_shift: u64, fee: u64) -> Result<Self, Error> {
		if fee == 0 {
			Err(Error::InvalidFeeFields)
		} else if fee > FeeFields::FEE_MASK {
			Err(Error::InvalidFeeFields)
		} else if fee_shift > FeeFields::FEE_SHIFT_MASK {
			Err(Error::InvalidFeeFields)
		} else {
			Ok(Self((fee_shift << FeeFields::FEE_BITS) | fee))
		}
	}

	/// Extract fee_shift field
	pub fn fee_shift(&self, _height: u64) -> u8 {
		((self.0 >> FeeFields::FEE_BITS) & FeeFields::FEE_SHIFT_MASK) as u8
	}

	/// Extract fee field
	pub fn fee(&self, _height: u64) -> u64 {
		self.0 & FeeFields::FEE_MASK
	}

	/// Turn a zero `FeeField` into a `None`, any other value into a `Some`.
	/// We need this because a zero `FeeField` cannot be deserialized.
	pub fn as_opt(&self) -> Option<Self> {
		if self.is_zero() {
			None
		} else {
			Some(*self)
		}
	}

	/// Check if the `FeeFields` is set to zero
	pub fn is_zero(&self) -> bool {
		self.0 == 0
	}
}

fn fee_fields_as_int<S>(fee_fields: &FeeFields, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_u64(fee_fields.0)
}

/// Relative height field on NRD kernel variant.
/// u16 representing a height between 1 and MAX (consensus::WEEK_HEIGHT).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NRDRelativeHeight(u16);

impl DefaultHashable for NRDRelativeHeight {}

impl Writeable for NRDRelativeHeight {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u16(self.0)
	}
}

impl Readable for NRDRelativeHeight {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let x = reader.read_u16()?;
		NRDRelativeHeight::try_from(x).map_err(|_| ser::Error::CorruptedData)
	}
}

/// Conversion from a u16 to a valid NRDRelativeHeight.
/// Valid height is between 1 and WEEK_HEIGHT inclusive.
impl TryFrom<u16> for NRDRelativeHeight {
	type Error = Error;

	fn try_from(height: u16) -> Result<Self, Self::Error> {
		if height == 0 {
			Err(Error::InvalidNRDRelativeHeight)
		} else if height
			> NRDRelativeHeight::MAX
				.try_into()
				.expect("WEEK_HEIGHT const should fit in u16")
		{
			Err(Error::InvalidNRDRelativeHeight)
		} else {
			Ok(Self(height))
		}
	}
}

impl TryFrom<u64> for NRDRelativeHeight {
	type Error = Error;

	fn try_from(height: u64) -> Result<Self, Self::Error> {
		Self::try_from(u16::try_from(height).map_err(|_| Error::InvalidNRDRelativeHeight)?)
	}
}

impl From<NRDRelativeHeight> for u64 {
	fn from(height: NRDRelativeHeight) -> Self {
		height.0 as u64
	}
}

impl NRDRelativeHeight {
	const MAX: u64 = consensus::WEEK_HEIGHT;

	/// Create a new NRDRelativeHeight from the provided height.
	/// Checks height is valid (between 1 and WEEK_HEIGHT inclusive).
	pub fn new(height: u64) -> Result<Self, Error> {
		NRDRelativeHeight::try_from(height)
	}
}

/// Structure to hold the notarization data (limit 40 bytes)
#[derive(Clone, Copy)]
pub struct NotarizationData {
	/// Data to notarize. Must be exactly 40 bytes.
	pub data: [u8; 40],
}

impl DefaultHashable for NotarizationData {}
hashable_ord!(NotarizationData);

impl Writeable for NotarizationData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		for i in 0..40 {
			self.data[i].write(writer)?;
		}
		Ok(())
	}
}

impl fmt::Debug for NotarizationData {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		std::fmt::Display::fmt(
			&format!("NotizationData({})", self.data.to_hex()),
			formatter,
		)
	}
}

impl Serialize for NotarizationData {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.data.to_vec().to_hex().serialize(s)
	}
}

struct NotarizationDataVisitor;

impl<'di> de::Visitor<'di> for NotarizationDataVisitor {
	type Value = NotarizationData;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a byte array")
	}

	fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
	where
		E: de::Error,
	{
		let data_vec =
			util::from_hex(value).map_err(|_| E::custom(format!("notarization format invalid")))?;
		let mut data = [0 as u8; 40];
		for i in 0..40 {
			data[i] = data_vec[i];
		}
		Ok(NotarizationData { data })
	}
}

impl<'de> de::Deserialize<'de> for NotarizationData {
	fn deserialize<D>(d: D) -> Result<NotarizationData, D::Error>
	where
		D: de::Deserializer<'de>,
	{
		// Begin actual function
		d.deserialize_string(NotarizationDataVisitor)
	}
}

impl AsRef<[u8]> for NotarizationData {
	fn as_ref(&self) -> &[u8] {
		&self.data[..]
	}
}

/// Structure to hold the BTC signature
#[derive(Clone, Copy)]
pub struct BTCSignature {
	/// The signature for this BTC Claim
	pub signature: [u8; 65],
}

impl fmt::Debug for BTCSignature {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		std::fmt::Display::fmt(
			&format!(
				"Signature({})",
				&self.signature[..].to_vec().to_hex().to_string()
			),
			formatter,
		)
	}
}

impl PartialEq for BTCSignature {
	fn eq(&self, other: &Self) -> bool {
		for i in 0..65 {
			if self.signature[i] != other.signature[i] {
				return false;
			}
		}
		return true;
	}
}

impl Serialize for BTCSignature {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.signature.to_vec().to_hex().serialize(s)
	}
}

struct BTCSignatureVisitor;

impl<'di> de::Visitor<'di> for BTCSignatureVisitor {
	type Value = BTCSignature;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a string")
	}

	fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
	where
		E: de::Error,
	{
		let signature_vec =
			util::from_hex(value).map_err(|_| E::custom(format!("signature format invalid")))?;
		let mut signature = [0 as u8; 65];
		for i in 0..65 {
			signature[i] = signature_vec[i];
		}
		Ok(BTCSignature { signature })
	}
}

impl<'de> de::Deserialize<'de> for BTCSignature {
	fn deserialize<D>(d: D) -> Result<BTCSignature, D::Error>
	where
		D: de::Deserializer<'de>,
	{
		// Begin actual function
		d.deserialize_string(BTCSignatureVisitor)
	}
}

impl AsRef<[u8]> for BTCSignature {
	fn as_ref(&self) -> &[u8] {
		&self.signature[..]
	}
}

/// The BTC Redeem script
#[derive(Clone, Copy)]
pub struct RedeemScript {
	/// The data for this redeem script
	pub data: [u8; 520],
	/// The length of data for this redeem script
	pub len: usize,
}

impl fmt::Debug for RedeemScript {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		let len = if self.len < 520 { self.len } else { 520 };
		std::fmt::Display::fmt(
			&format!(
				"RedeemScript({})",
				&self.data[..len].to_vec().to_hex().to_string()
			),
			formatter,
		)
	}
}

impl PartialEq for RedeemScript {
	fn eq(&self, other: &Self) -> bool {
		let len = if self.len < 520 { self.len } else { 520 };
		for i in 0..len {
			if self.data[i] != other.data[i] {
				return false;
			}
		}
		return true;
	}
}

impl Serialize for RedeemScript {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let len = if self.len < 520 { self.len } else { 520 };
		self.data[..len].to_vec().to_hex().serialize(s)
	}
}

struct RedeemScriptVisitor;

impl<'di> de::Visitor<'di> for RedeemScriptVisitor {
	type Value = RedeemScript;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("a string")
	}

	fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
	where
		E: de::Error,
	{
		let data_vec = util::from_hex(value).map_err(|_| E::custom(format!("redeem not valid")))?;

		// we have a fixed length of 520 for serialization purposes and then we specify the 'len'
		let mut data = [0 as u8; 520];
		let data_vec_len = data_vec.len();
		let len = if data_vec_len < 520 {
			data_vec_len
		} else {
			520
		};
		for i in 0..len {
			data[i] = data_vec[i];
		}
		Ok(RedeemScript {
			data,
			len: data_vec.len(),
		})
	}
}

impl<'de> de::Deserialize<'de> for RedeemScript {
	fn deserialize<D>(d: D) -> Result<RedeemScript, D::Error>
	where
		D: de::Deserializer<'de>,
	{
		// Begin actual function
		d.deserialize_string(RedeemScriptVisitor)
	}
}

impl AsRef<[u8]> for RedeemScript {
	fn as_ref(&self) -> &[u8] {
		&self.data[..]
	}
}

/// Various tx kernel variants.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub enum KernelFeatures {
	/// Plain kernel (the default for Grin txs).
	Plain {
		/// Plain kernels have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
	},
	/// A coinbase kernel.
	Coinbase {
		/// Coinbase can add 40 bytes of additional data to be persisted in the blockchain.
		notarization_data: NotarizationData,
	},
	/// A kernel with an explicit lock height (and fee).
	HeightLocked {
		/// Height locked kernels have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
		/// Height locked kernels have lock heights.
		lock_height: u64,
	},
	/// "No Recent Duplicate" (NRD) kernels enforcing relative lock height between instances.
	NoRecentDuplicate {
		/// These have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
		/// Relative lock height.
		relative_height: NRDRelativeHeight,
	},
	/// Process a BTC Claim
	BTCClaim {
		/// These have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
		/// Index into the UTXO data array
		index: u32,
		/// The BTC Signature(s)
		btc_signatures: Vec<BTCSignature>,
		/// Redeem script for p2sh and p2wsh
		redeem_script: Option<RedeemScript>,
		/// address type
		address_type: u8,
	},
	/// Burn Kernel feature - provably burned amount specified
	Burn {
		/// Burn kernels have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
		/// amount burned by this kernel
		amount: u64,
	},
}

/// Create a BTCClaim Kernel Feature based on inputs
pub fn build_btc_init_kernel_feature(
	fee: FeeFields,
	index: u32,
	btc_sigs: Vec<RecoverableSignature>,
	btc_recovery_bytes: Vec<u8>,
	redeem_script: Option<RedeemScript>,
	address_type: u8,
) -> Result<KernelFeatures, self::Error> {
	let mut i = 0; // counter
	let mut btc_signatures = Vec::new();
	for btc_sig in btc_sigs {
		// get the compact version of each sig
		let (_rec_id, data) = btc_sig.serialize_compact();

		let mut signature = [0 as u8; 65];
		// use specified recovery_byte
		let recovery_byte = btc_recovery_bytes.get(i);
		if recovery_byte.is_none() {
			return Err(Error::RecoveryByteNotFound);
		}
		let recovery_byte = *recovery_byte.unwrap();
		signature[0] = recovery_byte;
		// copy the data over
		signature[1..].clone_from_slice(&data);
		// insert into the list
		btc_signatures.insert(i, BTCSignature { signature });
		i = i + 1;
	}

	Ok(KernelFeatures::BTCClaim {
		fee,
		index,
		btc_signatures,
		redeem_script,
		address_type,
	})
}

/// Get a RecoverableSignature from KernelFeatures::BTCClaim
pub fn get_recoverable_signature(
	kf: KernelFeatures,
	index: usize,
) -> Result<(u8, RecoverableSignature), bitcoin::secp256k1::Error> {
	match kf {
		KernelFeatures::BTCClaim { btc_signatures, .. } => {
			let mut data = [0 as u8; 64];
			// get the signature of the specified index
			let signature = btc_signatures.get(index);
			if signature.is_none() {
				return Err(bitcoin::secp256k1::Error::InvalidSignature);
			}

			let signature = signature.unwrap().signature;

			// get the recovery_id
			let rec_id = (signature[0] - 27) & 3;
			copy(&signature[1..], &mut data);

			// build recoverable signature
			match RecoveryId::from_i32(rec_id.into()) {
				Ok(r) => Ok((signature[0], RecoverableSignature::from_compact(&data, r)?)),
				Err(_) => Err(bitcoin::secp256k1::Error::InvalidMessage),
			}
		}
		_ => Err(bitcoin::secp256k1::Error::InvalidMessage),
	}
}

/// Get the Signature from the specified index
pub fn get_signature(
	kf: KernelFeatures,
	index: usize,
) -> Result<Signature, bitcoin::secp256k1::Error> {
	match kf {
		KernelFeatures::BTCClaim { btc_signatures, .. } => {
			//let mut data = [0 as u8; 64];
			// get the signature of the specified index
			let signature = btc_signatures.get(index);
			if signature.is_none() {
				return Err(bitcoin::secp256k1::Error::InvalidSignature);
			}

			let signature = signature.unwrap().signature;

			let rec_id = (signature[0] - 27) & 3;

			// build recoverable signature
			match RecoveryId::from_i32(rec_id.into()) {
				Ok(r) => Ok(RecoverableSignature::from_compact(&signature[1..], r)?.to_standard()),
				Err(_) => Err(bitcoin::secp256k1::Error::InvalidMessage),
			}
		}
		_ => Err(bitcoin::secp256k1::Error::InvalidMessage),
	}
}

impl KernelFeatures {
	const PLAIN_U8: u8 = 0;
	const COINBASE_U8: u8 = 1;
	const HEIGHT_LOCKED_U8: u8 = 2;
	const NO_RECENT_DUPLICATE_U8: u8 = 3;
	const BTCCLAIM_U8: u8 = 4;
	const BURN_U8: u8 = 5;

	/// Underlying (u8) value representing this kernel variant.
	/// This is the first byte when we serialize/deserialize the kernel features.
	pub fn as_u8(&self) -> u8 {
		match self {
			KernelFeatures::Plain { .. } => KernelFeatures::PLAIN_U8,
			KernelFeatures::Coinbase { .. } => KernelFeatures::COINBASE_U8,
			KernelFeatures::HeightLocked { .. } => KernelFeatures::HEIGHT_LOCKED_U8,
			KernelFeatures::NoRecentDuplicate { .. } => KernelFeatures::NO_RECENT_DUPLICATE_U8,
			KernelFeatures::BTCClaim { .. } => KernelFeatures::BTCCLAIM_U8,
			KernelFeatures::Burn { .. } => KernelFeatures::BURN_U8,
		}
	}

	/// Conversion for backward compatibility.
	pub fn as_string(&self) -> String {
		match self {
			KernelFeatures::Plain { .. } => String::from("Plain"),
			KernelFeatures::Coinbase { .. } => String::from("Coinbase"),
			KernelFeatures::HeightLocked { .. } => String::from("HeightLocked"),
			KernelFeatures::NoRecentDuplicate { .. } => String::from("NoRecentDuplicate"),
			KernelFeatures::BTCClaim { .. } => String::from("BTCClaim"),
			KernelFeatures::Burn { .. } => String::from("Burn"),
		}
	}

	/// msg = hash(features)                                  for coinbase kernels
	///       hash(features || fee_fields)                    for plain kernels
	///       hash(features || fee_fields || lock_height)     for height locked kernels
	///       hash(features || fee_fields || relative_height) for NRD kernels
	///       hash(features || fee_fields || index)           for BTCClaim kernels
	pub fn kernel_sig_msg(&self) -> Result<secp::Message, Error> {
		let x = self.as_u8();
		let hash = match self {
			KernelFeatures::Plain { fee } => (x, fee).hash(),
			KernelFeatures::Coinbase { notarization_data } => (x, notarization_data).hash(),
			KernelFeatures::HeightLocked { fee, lock_height } => (x, fee, lock_height).hash(),
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height,
			} => (x, fee, relative_height).hash(),
			KernelFeatures::BTCClaim { fee, index, .. } => (x, fee, *index as u64).hash(),
			KernelFeatures::Burn { fee, amount } => (x, fee, amount).hash(),
		};

		let msg = secp::Message::from_slice(&hash.as_bytes())?;
		Ok(msg)
	}

	/// Write tx kernel features out in v2 protocol format.
	/// These are variable sized based on feature variant.
	/// Only write fee_fields out for feature variants that support it.
	/// Only write lock_height out for feature variants that support it.
	fn write_v2<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.as_u8())?;
		match self {
			KernelFeatures::Plain { fee } => {
				// Fee only, no additional data on plain kernels.
				fee.write(writer)?;
			}
			KernelFeatures::Coinbase { notarization_data } => {
				for i in 0..40 {
					writer.write_u8(notarization_data.data[i])?;
				}
			}
			KernelFeatures::HeightLocked { fee, lock_height } => {
				fee.write(writer)?;
				// V2 height locked kernels use 8 bytes for the lock height.
				writer.write_u64(*lock_height)?;
			}
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height,
			} => {
				fee.write(writer)?;
				// V2 NRD kernels use 2 bytes for the relative lock height.
				relative_height.write(writer)?;
			}
			KernelFeatures::BTCClaim {
				fee,
				index,
				btc_signatures,
				redeem_script,
				address_type,
			} => {
				fee.write(writer)?;
				index.write(writer)?;
				let len_u32: Result<u32, _> = btc_signatures.len().try_into();
				if len_u32.is_err() {
					return Err(ser::Error::TooLargeReadErr);
				}
				let len_u32 = len_u32.unwrap();
				len_u32.write(writer)?;

				// write each of the signatures
				for sig in btc_signatures {
					for i in 0..65 {
						writer.write_u8(sig.signature[i])?;
					}
				}

				// if there's a redeem script serialize it
				if redeem_script.is_some() {
					let redeem_script = redeem_script.unwrap();
					// present
					writer.write_u8(1)?;
					writer.write_u32(redeem_script.len as u32)?;
					for i in 0..520 {
						writer.write_u8(redeem_script.data[i])?;
					}
				} else {
					// not present
					writer.write_u8(0)?;
				}
				writer.write_u8(*address_type)?;
			}
			KernelFeatures::Burn { fee, amount } => {
				fee.write(writer)?;
				writer.write_u64(*amount)?;
			}
		}
		Ok(())
	}

	// V2 kernels only expect bytes specific to each variant.
	// Coinbase kernels have no associated fee and we do not serialize a fee for these.
	fn read_v2<R: Reader>(reader: &mut R) -> Result<KernelFeatures, ser::Error> {
		let features = match reader.read_u8()? {
			KernelFeatures::PLAIN_U8 => {
				let fee = FeeFields::read(reader)?;
				KernelFeatures::Plain { fee }
			}
			KernelFeatures::COINBASE_U8 => {
				let mut data = [0 as u8; 40];
				for i in 0..40 {
					data[i] = reader.read_u8()?;
				}

				KernelFeatures::Coinbase {
					notarization_data: NotarizationData { data },
				}
			}
			KernelFeatures::HEIGHT_LOCKED_U8 => {
				let fee = FeeFields::read(reader)?;
				let lock_height = reader.read_u64()?;
				KernelFeatures::HeightLocked { fee, lock_height }
			}
			KernelFeatures::NO_RECENT_DUPLICATE_U8 => {
				// NRD kernels are invalid if NRD feature flag is not enabled.
				if !global::is_nrd_enabled() {
					return Err(ser::Error::CorruptedData);
				}

				let fee = FeeFields::read(reader)?;
				let relative_height = NRDRelativeHeight::read(reader)?;
				KernelFeatures::NoRecentDuplicate {
					fee,
					relative_height,
				}
			}
			KernelFeatures::BTCCLAIM_U8 => {
				let fee = FeeFields::read(reader)?;
				let index = reader.read_u32()?;
				let len = reader.read_u32()?;
				let mut btc_signatures: Vec<BTCSignature> = Vec::new();

				// read each signature
				for i in 0..len {
					let mut signature = [0 as u8; 65];
					for i in 0..65 {
						signature[i] = reader.read_u8()?;
					}
					let btc_signature = BTCSignature { signature };
					btc_signatures.insert(i as usize, btc_signature);
				}

				// read this byte to determine if there's a redeem script
				let redeem_script = match reader.read_u8()? {
					0 => None,
					_ => {
						// it's present, read the 520 byte redeem script
						let len = reader.read_u32()?;
						let mut r: RedeemScript = RedeemScript {
							data: [0 as u8; 520],
							len: len.try_into().unwrap(),
						};
						for i in 0..520 {
							r.data[i] = reader.read_u8()?;
						}
						Some(r)
					}
				};

				let address_type = reader.read_u8()?;

				KernelFeatures::BTCClaim {
					fee,
					index,
					btc_signatures,
					redeem_script,
					address_type,
				}
			}
			KernelFeatures::BURN_U8 => {
				let fee = FeeFields::read(reader)?;
				let amount = reader.read_u64()?;
				KernelFeatures::Burn { fee, amount }
			}
			_ => {
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(features)
	}
}

impl Writeable for KernelFeatures {
	/// Protocol version may increment rapidly for other unrelated changes.
	/// So we match on ranges here and not specific version values.
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// since we have no legacy v1 kernel data, we always use v2 here.
		return self.write_v2(writer);
	}
}

impl Readable for KernelFeatures {
	fn read<R: Reader>(reader: &mut R) -> Result<KernelFeatures, ser::Error> {
		// no legacy data so always read v2 here.
		KernelFeatures::read_v2(reader)
	}
}

/// Errors thrown by Transaction validation
#[derive(Clone, Eq, Debug, PartialEq, Serialize, Deserialize)]
pub enum Error {
	/// Underlying Secp256k1 error (signature validation or invalid public key
	/// typically)
	Secp(secp::Error),
	/// Underlying keychain related error
	Keychain(keychain::Error),
	/// The sum of output minus input commitments does not
	/// match the sum of kernel commitments
	KernelSumMismatch,
	/// Restrict tx total weight.
	TooHeavy,
	/// Error originating from an invalid lock-height
	LockHeight(u64),
	/// Range proof validation error
	RangeProof,
	/// Error originating from an invalid Merkle proof
	MerkleProof,
	/// Returns if the value hidden within the a RangeProof message isn't
	/// repeated 3 times, indicating it's incorrect
	InvalidProofMessage,
	/// Error when verifying kernel sums via committed trait.
	Committed(committed::Error),
	/// Validation error relating to cut-through (tx is spending its own
	/// output).
	CutThrough,
	/// Validation error relating to output features.
	/// It is invalid for a transaction to contain a coinbase output, for example.
	InvalidOutputFeatures,
	/// Validation error relating to kernel features.
	/// It is invalid for a transaction to contain a coinbase kernel, for example.
	InvalidKernelFeatures,
	/// There are more than one notary kernels in this txn.
	MultipleNotaryKernelFeatures,
	/// Maximum burn of 100,000 BMWs is exceeded.
	MaxBurnExceeded,
	/// RecoveryByte Not found for this BTCKernel.
	RecoveryByteNotFound,
	/// feeshift is limited to 4 bits and fee must be positive and fit in 40 bits.
	InvalidFeeFields,
	/// NRD kernel relative height is limited to 1 week duration and must be greater than 0.
	InvalidNRDRelativeHeight,
	/// Signature verification error.
	IncorrectSignature,
	/// Underlying serialization error.
	Serialization(ser::Error),
	/// UtxoData error
	UtxoDataError(String),
	/// The type of Kernel Features was not expected here.
	UnexpectedKernelFeaturesType,
	/// The BTCSignature was invalid
	InvalidBTCSignature,
	/// Redeem Script is not found in the claim db
	InvalidRedeemScript,
	/// Invalid BTC Claim
	InvalidBTCClaim,
	/// No BTC Signature
	NoSignature,
	/// Too Many Keys
	TooManyKeys,
	/// The btc address was invalid
	InvalidBTCAddress,
	/// No utxo_data
	NoUtxoData,
	/// Invalid witness address
	InvalidWitnessAddress(String),
	/// Other
	Other(String),
}

impl error::Error for Error {
	fn description(&self) -> &str {
		match *self {
			_ => "transaction error",
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			_ => write!(f, "some kind of transaction error"),
		}
	}
}

impl From<ser::Error> for Error {
	fn from(e: ser::Error) -> Error {
		Error::Serialization(e)
	}
}

impl From<bmw_utxo::error::Error> for Error {
	fn from(e: bmw_utxo::error::Error) -> Error {
		Error::UtxoDataError(format!("{:?}", e))
	}
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

impl From<bitcoin::util::address::Error> for Error {
	fn from(e: bitcoin::util::address::Error) -> Error {
		Error::InvalidWitnessAddress(e.to_string())
	}
}

impl From<keychain::Error> for Error {
	fn from(e: keychain::Error) -> Error {
		Error::Keychain(e)
	}
}

impl From<committed::Error> for Error {
	fn from(e: committed::Error) -> Error {
		Error::Committed(e)
	}
}

/// A proof that a transaction sums to zero. Includes both the transaction's
/// Pedersen commitment and the signature, that guarantees that the commitments
/// amount to zero.
/// The signature signs the fee_fields and the lock_height, which are retained for
/// signature validation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxKernel {
	/// Options for a kernel's structure or use
	pub features: KernelFeatures,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key (sum of the commitment public keys).
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee_fields.
	#[serde(with = "secp_ser::sig_serde")]
	pub excess_sig: secp::Signature,
}

impl DefaultHashable for TxKernel {}
hashable_ord!(TxKernel);

/// We want to be able to put kernels in a hashset in the pool.
/// So we need to be able to hash them.
impl ::std::hash::Hash for TxKernel {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

impl Writeable for TxKernel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.excess.write(writer)?;
		self.excess_sig.write(writer)?;
		Ok(())
	}
}

impl Readable for TxKernel {
	fn read<R: Reader>(reader: &mut R) -> Result<TxKernel, ser::Error> {
		Ok(TxKernel {
			features: KernelFeatures::read(reader)?,
			excess: Commitment::read(reader)?,
			excess_sig: secp::Signature::read(reader)?,
		})
	}
}

/// We store kernels in the kernel MMR.
/// Note: These are "variable size" to support different kernel feature variants.
impl PMMRable for TxKernel {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}

	fn elmt_size() -> Option<u16> {
		None
	}
}

impl KernelFeatures {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		match self {
			KernelFeatures::Coinbase { .. } => true,
			_ => false,
		}
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		match self {
			KernelFeatures::Plain { .. } => true,
			_ => false,
		}
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		match self {
			KernelFeatures::HeightLocked { .. } => true,
			_ => false,
		}
	}

	/// Is this an NRD kernel?
	pub fn is_nrd(&self) -> bool {
		match self {
			KernelFeatures::NoRecentDuplicate { .. } => true,
			_ => false,
		}
	}
}

impl TxKernel {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		self.features.is_height_locked()
	}

	/// Is this an NRD kernel?
	pub fn is_nrd(&self) -> bool {
		self.features.is_nrd()
	}

	/// Return the excess commitment for this tx_kernel.
	pub fn excess(&self) -> Commitment {
		self.excess
	}

	/// The msg signed as part of the tx kernel.
	/// Based on kernel features and associated fields (fee_fields and lock_height).
	pub fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self.features.kernel_sig_msg()?;
		Ok(msg)
	}

	/// Verify the transaction proof validity. Entails handling the commitment
	/// as a public key and checking the signature verifies with the fee_fields as
	/// message.
	pub fn verify(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let sig = &self.excess_sig;
		// Verify aggsig directly in libsecp
		let pubkey = &self.excess.to_pubkey(&secp)?;
		if !aggsig::verify_single(
			&secp,
			&sig,
			&self.msg_to_sign()?,
			None,
			&pubkey,
			Some(&pubkey),
			false,
		) {
			return Err(Error::IncorrectSignature);
		}
		Ok(())
	}

	/// Validate a BTC Claim if it exists in this kernel
	pub fn validate_btcclaim(
		&self,
		utxo_data: Option<Weak<RwLock<UtxoData>>>,
	) -> Result<(), Error> {
		match &self.features {
			KernelFeatures::BTCClaim {
				btc_signatures,
				index,
				redeem_script,
				address_type,
				..
			} => {
				if redeem_script.is_some() {
					if *address_type != P2SH && *address_type != P2WSH && *address_type != P2SHWSH {
						return Err(Error::InvalidBTCClaim);
					};
					self.process_redeem(
						utxo_data,
						&btc_signatures,
						&index,
						&redeem_script,
						*address_type,
					)?;
				} else {
					self.process_single_sig(utxo_data, &btc_signatures, &index)?;
				}
			}
			_ => {}
		}
		Ok(())
	}

	/// Get the message from the challenge string
	fn get_message_from_challenge(&self, challenge: String) -> Message {
		let hash = misc::signed_msg_hash(&challenge);
		Message::from_slice(&hash[..]).unwrap()
	}

	/// Checks that the btc signature is valid
	fn check_btc_signature(
		&self,
		address: String,
		challenge_str: String,
		rec_sig: RecoverableSignature,
		btc_recovery_byte: u8,
	) -> Result<(), Error> {
		let secp = Secp256k1::verification_only();
		// build message from challenge_string
		let msg = self.get_message_from_challenge(challenge_str);
		// get pubkey from recoverable signature
		let mut pubkey = BitcoinPublicKey {
			key: secp
				.recover(&msg, &rec_sig)
				.map_err(|_| Error::InvalidBTCSignature)?,
			compressed: ((btc_recovery_byte - 27) & 4) != 0,
		};

		// get the recovered address
		let address_rec = if address.starts_with("1") {
			Ok(Address::p2pkh(&pubkey, Bitcoin))
		} else if address.starts_with("3") {
			// for this address type, must be compressed.
			pubkey.compressed = true;
			Address::p2shwpkh(&pubkey, Bitcoin)
		} else if address.starts_with("bc1") {
			// for this address type, must be compressed.
			pubkey.compressed = true;
			Address::p2wpkh(&pubkey, Bitcoin)
		} else {
			return Err(Error::InvalidBTCAddress);
		};

		// if there's an error doing that, throw error.
		if address_rec.is_err() {
			return Err(Error::InvalidBTCAddress);
		}

		let address_rec = address_rec.unwrap();

		// if the recovered address doesn't match the specified adress,
		// throw an error
		if format!("{}", address_rec) != address {
			return Err(Error::InvalidBTCSignature);
		}

		// otherwise, success
		Ok(())
	}

	/// Process a normal single signature BTC claim
	/// Throw an error if anything is wrong
	fn process_single_sig(
		&self,
		utxo_data: Option<Weak<RwLock<UtxoData>>>,
		btc_signatures: &Vec<BTCSignature>,
		index: &u32,
	) -> Result<(), Error> {
		if utxo_data.is_none() {
			return Err(Error::NoUtxoData);
		}
		let utxo_data = utxo_data.unwrap().upgrade().unwrap();
		let utxo_data = utxo_data.read();

		// Something's wrong if there's no redeem and there's more than 1 sig.
		if btc_signatures.len() != 1 {
			return Err(Error::InvalidBTCClaim);
		}

		// get the btc_signature (only the first one.
		let btc_signature = btc_signatures.get(0);
		// if it's none, throw error
		if btc_signature.is_none() {
			return Err(Error::InvalidBTCSignature);
		}
		let btc_signature = btc_signature.unwrap();

		// first byte is the recovery byte.
		let btc_recovery_byte = btc_signature.signature[0];
		// build a recoverable signature.
		let (_, rec_sig) = get_recoverable_signature(self.features.clone(), 0)
			.map_err(|_| Error::InvalidBTCSignature)?;

		let challenge_str = self.get_challenge();

		let address = (*utxo_data).get_address(*index);
		// if the address is not found, throw an error.
		if !address.is_ok() {
			return Err(Error::InvalidBTCSignature);
		}

		let address = address.unwrap();

		// check btc signature.
		self.check_btc_signature(address, challenge_str, rec_sig, btc_recovery_byte)?;

		Ok(())
	}

	fn get_challenge(&self) -> String {
		// build the expected challenge based on kernel excess
		let excess = format!("{:?}", self.excess);
		let excess = excess.replace("Commitment(", "");
		let excess = excess.replace(")", "");
		let challenge_str = format!("bmw{}", excess);
		challenge_str
	}

	/// Process a BTCClaim that has a redeem script
	fn process_redeem(
		&self,
		utxo_data: Option<Weak<RwLock<UtxoData>>>,
		btc_signatures: &Vec<BTCSignature>,
		index: &u32,
		redeem_script: &Option<RedeemScript>,
		address_type: u8,
	) -> Result<(), Error> {
		if utxo_data.is_none() {
			return Err(Error::NoUtxoData);
		}
		let utxo_data = utxo_data.unwrap().upgrade().unwrap();
		let utxo_data = utxo_data.read();

		// get redeem script
		let redeem_script = redeem_script.unwrap();

		// convert the redeem_script's data to a vec.
		let mut data_vec = redeem_script.data.to_vec();
		// truncate to the length of the script.
		data_vec.truncate(redeem_script.len);
		// convert into a script
		let script: Script = data_vec.into();

		let is_witness;
		// get address based on this script's hash depending on address_type.
		let address = if address_type == P2SH {
			is_witness = false;
			Address::p2sh(&script, Bitcoin)
		} else if address_type == P2SHWSH {
			is_witness = true;
			Address::p2shwsh(&script, Bitcoin)
		} else if address_type == P2WSH {
			is_witness = true;
			Address::p2wsh(&script, Bitcoin)
		} else {
			return Err(Error::InvalidBTCClaim);
		};

		// is it found in our utxo_data?
		let index_found = (*utxo_data).get_index(format!("{}", address).to_string());

		if index_found.is_err() {
			return Err(Error::InvalidRedeemScript);
		}

		let index_found = index_found.unwrap();
		// if the index is not the one that was specified in the kernel, throw an error.
		if index_found != *index {
			return Err(Error::InvalidBTCClaim);
		}

		// iterate through the script to count the number of keys required to process it.
		// having more keys than needed is an error because it would fill up the blockchain.
		let mut key_count = 0;
		let mut instruction_counter = script.instructions();
		loop {
			let next = instruction_counter.next();

			if next.is_none() {
				break;
			}
			let next = next.unwrap();

			// if next is an error throw InvalidBTCClaim
			if next.is_err() {
				return Err(Error::InvalidBTCClaim);
			}

			let next = next.unwrap();

			match next {
				PushBytes(_) => {
					key_count += 1;
				}
				_ => {}
			}
		}

		// if there's more signatures than needed, throw error.
		if btc_signatures.len() > key_count {
			return Err(Error::TooManyKeys);
		}

		// obtain the challenge message.
		let mut instructions = script.instructions();

		// loop through the instructions. Check each one.
		let mut last_op = 1;
		let mut cur_verified = 0;
		let mut last_type_is_op = true;
		loop {
			let next = instructions.next();

			if next.is_none() {
				break;
			}
			let next = next.unwrap();

			if next.is_err() {
				return Err(Error::InvalidBTCClaim);
			}

			let next = next.unwrap();

			match next {
				Op(n) => {
					if !last_type_is_op {
						// check the verification
						if cur_verified < last_op {
							return Err(Error::NoSignature);
						}
					}

					last_op = if n == OP_PUSHNUM_1 {
						1
					} else if n == OP_PUSHNUM_2 {
						2
					} else if n == OP_PUSHNUM_3 {
						3
					} else if n == OP_PUSHNUM_4 {
						4
					} else if n == OP_PUSHNUM_5 {
						5
					} else if n == OP_PUSHNUM_6 {
						6
					} else if n == OP_PUSHNUM_7 {
						7
					} else if n == OP_PUSHNUM_8 {
						8
					} else if n == OP_PUSHNUM_9 {
						9
					} else if n == OP_PUSHNUM_10 {
						10
					} else if n == OP_PUSHNUM_11 {
						11
					} else if n == OP_PUSHNUM_12 {
						12
					} else if n == OP_PUSHNUM_13 {
						13
					} else if n == OP_PUSHNUM_14 {
						14
					} else if n == OP_PUSHNUM_15 {
						15
					} else if n == OP_PUSHNUM_16 {
						16
					} else {
						// anything else goes here
						0
					};
					cur_verified = 0;
					last_type_is_op = true;
				}
				PushBytes(data) => {
					// if next is a push bytes, check all signatures. If no match is found
					// it's an error.
					// we only require a single signature for non-multisig scripts.

					// get the pubkey
					let pubkey = bitcoin::PublicKey::from_slice(data);
					if pubkey.is_err() {
						return Err(Error::InvalidBTCClaim);
					}
					let pubkey = pubkey.unwrap();

					let mut count = 0;

					for _ in btc_signatures {
						let address = if is_witness {
							Address::p2wpkh(&pubkey, Bitcoin)?
						} else {
							Address::p2pkh(&pubkey, Bitcoin)
						};
						// check each signature until a valid one is found
						let (rec_byte, sig) =
							get_recoverable_signature(self.features.clone(), count)
								.map_err(|_| Error::InvalidBTCSignature)?;

						let challenge_str = self.get_challenge();
						let verify = self
							.check_btc_signature(address.to_string(), challenge_str, sig, rec_byte)
							.is_ok();
						if verify {
							cur_verified += 1;
							break;
						}
						count = count + 1;
						last_type_is_op = false;
					}

					// if this is not a OP_PUSHNUM_N (last_op == 0), we require all signatures
					// last_op == 0 means something other than an OP_PUSHNUM_N, we don't know what
					// to do, so just require all signatures in this case.
					if last_op == 0 && cur_verified == 0 {
						return Err(Error::NoSignature);
					}
				}
			}
		}

		Ok(())
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(tx_kernels: &[TxKernel]) -> Result<(), Error> {
		let len = tx_kernels.len();
		let mut sigs = Vec::with_capacity(len);
		let mut pubkeys = Vec::with_capacity(len);
		let mut msgs = Vec::with_capacity(len);

		let secp = static_secp_instance();
		let secp = secp.lock();

		for tx_kernel in tx_kernels {
			sigs.push(tx_kernel.excess_sig);
			pubkeys.push(tx_kernel.excess.to_pubkey(&secp)?);
			msgs.push(tx_kernel.msg_to_sign()?);
		}

		if !aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}

	/// Build an empty tx kernel with zero values.
	pub fn empty() -> TxKernel {
		TxKernel::with_features(KernelFeatures::Plain {
			fee: FeeFields::zero(),
		})
	}

	/// Build an empty tx kernel with the provided kernel features.
	pub fn with_features(features: KernelFeatures) -> TxKernel {
		TxKernel {
			features,
			excess: Commitment::from_vec(vec![0; 33]),
			excess_sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		}
	}
}

/// Enum of possible tx weight verification options -
///
/// * As "transaction" checks tx (as block) weight does not exceed max_block_weight.
/// * As "block" same as above but allow for additional coinbase reward (1 output, 1 kernel).
/// * With "no limit" to skip the weight check.
///
#[derive(Clone, Copy)]
pub enum Weighting {
	/// Tx represents a tx (max block weight, accounting for additional coinbase reward).
	AsTransaction,
	/// Tx representing a tx with artificially limited max_weight.
	/// This is used when selecting mineable txs from the pool.
	AsLimitedTransaction(u64),
	/// Tx represents a block (max block weight).
	AsBlock,
	/// No max weight limit (skip the weight check).
	NoLimit,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransactionBody {
	/// List of inputs spent by the transaction.
	pub inputs: Inputs,
	/// List of outputs the transaction produces.
	pub outputs: Vec<Output>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernel>,
}

/// Implementation of Writeable for a body, defines how to
/// write the body as binary.
impl Writeable for TransactionBody {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(
			writer,
			[write_u64, self.inputs.len() as u64],
			[write_u64, self.outputs.len() as u64],
			[write_u64, self.kernels.len() as u64]
		);

		self.inputs.write(writer)?;
		self.outputs.write(writer)?;
		self.kernels.write(writer)?;

		Ok(())
	}
}

/// Implementation of Readable for a body, defines how to read a
/// body from a binary stream.
impl Readable for TransactionBody {
	fn read<R: Reader>(reader: &mut R) -> Result<TransactionBody, ser::Error> {
		let (num_inputs, num_outputs, num_kernels) =
			ser_multiread!(reader, read_u64, read_u64, read_u64);

		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		let tx_block_weight = TransactionBody::weight_by_iok(num_inputs, num_outputs, num_kernels);
		if tx_block_weight > global::max_block_weight() {
			return Err(ser::Error::TooLargeReadErr);
		}

		let inputs: Vec<CommitWrapper> = read_multi(reader, num_inputs)?;
		let inputs = Inputs::from(inputs.as_slice());
		let outputs = read_multi(reader, num_outputs)?;
		let kernels = read_multi(reader, num_kernels)?;

		// Initialize tx body and verify everything is sorted.
		let body = TransactionBody::init(inputs, &outputs, &kernels, true)
			.map_err(|_| ser::Error::CorruptedData)?;

		Ok(body)
	}
}

impl Committed for TransactionBody {
	fn inputs_committed(&self) -> Vec<Commitment> {
		let inputs: Vec<_> = self.inputs().into();
		inputs.iter().map(|x| x.commitment()).collect()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.outputs().iter().map(|x| x.commitment()).collect()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.kernels().iter().map(|x| x.excess()).collect()
	}
}

impl Default for TransactionBody {
	fn default() -> TransactionBody {
		TransactionBody::empty()
	}
}

impl From<Transaction> for TransactionBody {
	fn from(tx: Transaction) -> Self {
		tx.body
	}
}

impl TransactionBody {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> TransactionBody {
		TransactionBody {
			inputs: Inputs::default(),
			outputs: vec![],
			kernels: vec![],
		}
	}

	/// Sort the inputs|outputs|kernels.
	pub fn sort(&mut self) {
		self.inputs.sort_unstable();
		self.outputs.sort_unstable();
		self.kernels.sort_unstable();
	}

	/// Creates a new transaction body initialized with
	/// the provided inputs, outputs and kernels.
	/// Guarantees inputs, outputs, kernels are sorted lexicographically.
	pub fn init(
		inputs: Inputs,
		outputs: &[Output],
		kernels: &[TxKernel],
		verify_sorted: bool,
	) -> Result<TransactionBody, Error> {
		let mut body = TransactionBody {
			inputs,
			outputs: outputs.to_vec(),
			kernels: kernels.to_vec(),
		};

		if verify_sorted {
			// If we are verifying sort order then verify and
			// return an error if not sorted lexicographically.
			body.verify_sorted()?;
		} else {
			// If we are not verifying sort order then sort in place and return.
			body.sort();
		}
		Ok(body)
	}

	/// Transaction inputs.
	pub fn inputs(&self) -> Inputs {
		self.inputs.clone()
	}

	/// Transaction outputs.
	pub fn outputs(&self) -> &[Output] {
		&self.outputs
	}

	/// Transaction kernels.
	pub fn kernels(&self) -> &[TxKernel] {
		&self.kernels
	}

	/// Builds a new body with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(mut self, input: Input) -> TransactionBody {
		self.inputs.add(input.into());
		self
	}

	/// Builds a new body with the provided inputs (w/ signature) added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input_wsig(mut self, input_with_sig: CommitWrapper) -> TransactionBody {
		self.inputs.add(input_with_sig);
		self
	}

	/// Fully replace inputs.
	pub fn replace_inputs(mut self, inputs: Inputs) -> TransactionBody {
		self.inputs = inputs;
		self
	}

	/// Builds a new TransactionBody with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(mut self, output: Output) -> TransactionBody {
		if let Err(e) = self.outputs.binary_search(&output) {
			self.outputs.insert(e, output)
		};
		self
	}

	/// Fully replace outputs.
	pub fn replace_outputs(mut self, outputs: &[Output]) -> TransactionBody {
		self.outputs = outputs.to_vec();
		self
	}

	/// Builds a new TransactionBody with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(mut self, kernel: TxKernel) -> TransactionBody {
		if let Err(e) = self.kernels.binary_search(&kernel) {
			self.kernels.insert(e, kernel)
		};
		self
	}

	/// Builds a new TransactionBody replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(mut self, kernel: TxKernel) -> TransactionBody {
		self.kernels.clear();
		self.kernels.push(kernel);
		self
	}

	/// Total fee for a TransactionBody is the sum of fees of all fee carrying kernels.
	pub fn fee(&self, height: u64) -> u64 {
		self.kernels
			.iter()
			.filter_map(|k| match k.features {
				KernelFeatures::Coinbase { .. } => None,
				KernelFeatures::Plain { fee } => Some(fee),
				KernelFeatures::HeightLocked { fee, .. } => Some(fee),
				KernelFeatures::NoRecentDuplicate { fee, .. } => Some(fee),
				KernelFeatures::BTCClaim { fee, .. } => Some(fee),
				KernelFeatures::Burn { fee, .. } => Some(fee),
			})
			.fold(0, |acc, fee_fields| {
				acc.saturating_add(fee_fields.fee(height))
			})
	}

	/// fee_shift for a TransactionBody is the maximum of fee_shifts of all fee carrying kernels.
	pub fn fee_shift(&self, height: u64) -> u8 {
		self.kernels
			.iter()
			.filter_map(|k| match k.features {
				KernelFeatures::Coinbase { .. } => None,
				KernelFeatures::Plain { fee } => Some(fee),
				KernelFeatures::HeightLocked { fee, .. } => Some(fee),
				KernelFeatures::NoRecentDuplicate { fee, .. } => Some(fee),
				KernelFeatures::BTCClaim { fee, .. } => Some(fee),
				KernelFeatures::Burn { fee, .. } => Some(fee),
			})
			.fold(0, |acc, fee_fields| max(acc, fee_fields.fee_shift(height)))
	}

	/// Shifted fee for a TransactionBody is the sum of fees shifted right by the maximum fee_shift
	/// this is used to determine whether a tx can be relayed or accepted in a mempool
	/// where transactions can specify a higher block-inclusion priority as a positive shift up to 15
	/// but are required to overpay the minimum required fees by a factor of 2^priority
	pub fn shifted_fee(&self, height: u64) -> u64 {
		self.fee(height) >> self.fee_shift(height)
	}

	/// aggregate fee_fields from all appropriate kernels in TransactionBody into one, if possible
	pub fn aggregate_fee_fields(&self, height: u64) -> Result<FeeFields, Error> {
		FeeFields::new(self.fee_shift(height) as u64, self.fee(height))
	}

	fn overage(
		&self,
		height: u64,
		utxo_data: Option<Weak<RwLock<UtxoData>>>,
		amount: Option<u64>,
	) -> i64 {
		let mut btc_init_amt: i64 = 0;

		// if amount is passed in we use it as the wallet
		if amount.is_some() {
			btc_init_amt -= amount.unwrap() as i64;
		}
		if utxo_data.is_some() {
			let utxo_data = &*utxo_data.unwrap().upgrade().unwrap();
			let utxo_data = utxo_data.read();

			for kernel in self.kernels.clone() {
				match kernel.features {
					KernelFeatures::BTCClaim { index, .. } => {
						let amount = (*utxo_data).get_sats_by_index(index);
						if amount.is_ok() {
							btc_init_amt -= (amount.unwrap() * 10) as i64;
						}
					}
					_ => {}
				}
			}
		}

		let mut burn_amount: i64 = 0;

		for kernel in self.kernels.clone() {
			match kernel.features {
				KernelFeatures::Burn { amount, .. } => {
					burn_amount += amount as i64;
				}
				_ => {}
			}
		}

		btc_init_amt + self.fee(height) as i64 + burn_amount
	}

	/// Calculate weight of transaction using block weighing
	pub fn weight(&self) -> u64 {
		TransactionBody::weight_by_iok(
			self.inputs.len() as u64,
			self.outputs.len() as u64,
			self.kernels.len() as u64,
		)
	}

	/// Calculate transaction weight using block weighing from transaction
	/// details. Consensus critical and uses consensus weight values.
	pub fn weight_by_iok(num_inputs: u64, num_outputs: u64, num_kernels: u64) -> u64 {
		num_inputs
			.saturating_mul(consensus::INPUT_WEIGHT as u64)
			.saturating_add(num_outputs.saturating_mul(consensus::OUTPUT_WEIGHT as u64))
			.saturating_add(num_kernels.saturating_mul(consensus::KERNEL_WEIGHT as u64))
	}

	/// Lock height of a body is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.kernels
			.iter()
			.filter_map(|x| match x.features {
				KernelFeatures::HeightLocked { lock_height, .. } => Some(lock_height),
				_ => None,
			})
			.max()
			.unwrap_or(0)
	}

	/// Verify the body is not too big in terms of number of inputs|outputs|kernels.
	/// Weight rules vary depending on the "weight type" (block or tx or pool).
	fn verify_weight(&self, weighting: Weighting) -> Result<(), Error> {
		// A coinbase reward is a single output and a single kernel (for now).
		// We need to account for this when verifying max tx weights.
		let coinbase_weight = consensus::OUTPUT_WEIGHT + consensus::KERNEL_WEIGHT;

		// If "tx" body then remember to reduce the max_block_weight by the weight of a kernel.
		// If "limited tx" then compare against the provided max_weight.
		// If "block" body then verify weight based on full set of inputs|outputs|kernels.
		// If "pool" body then skip weight verification (pool can be larger than single block).
		//
		// Note: Taking a max tx and building a block from it we need to allow room
		// for the additional coinbase reward (1 output + 1 kernel).
		//
		let max_weight = match weighting {
			Weighting::AsTransaction => global::max_tx_weight(),
			Weighting::AsLimitedTransaction(max_weight) => {
				min(global::max_block_weight(), max_weight).saturating_sub(coinbase_weight)
			}
			Weighting::AsBlock => global::max_block_weight(),
			Weighting::NoLimit => {
				// We do not verify "tx as pool" weight so we are done here.
				return Ok(());
			}
		};

		if self.weight() > max_weight {
			return Err(Error::TooHeavy);
		}
		Ok(())
	}

	// It is never valid to have multiple duplicate NRD kernels (by public excess)
	// in the same transaction or block. We check this here.
	// We skip this check if NRD feature is not enabled.
	fn verify_no_nrd_duplicates(&self) -> Result<(), Error> {
		if !global::is_nrd_enabled() {
			return Ok(());
		}

		let mut nrd_excess: Vec<Commitment> = self
			.kernels
			.iter()
			.filter(|x| match x.features {
				KernelFeatures::NoRecentDuplicate { .. } => true,
				_ => false,
			})
			.map(|x| x.excess())
			.collect();

		// Sort and dedup and compare length to look for duplicates.
		nrd_excess.sort();
		let original_count = nrd_excess.len();
		nrd_excess.dedup();
		let dedup_count = nrd_excess.len();
		if original_count == dedup_count {
			Ok(())
		} else {
			Err(Error::InvalidNRDRelativeHeight)
		}
	}

	// Verify that inputs|outputs|kernels are sorted in lexicographical order
	// and that there are no duplicates (they are all unique within this transaction).
	fn verify_sorted(&self) -> Result<(), Error> {
		self.inputs.verify_sorted_and_unique()?;
		self.outputs.verify_sorted_and_unique()?;
		self.kernels.verify_sorted_and_unique()?;
		Ok(())
	}

	// Returns a single sorted vec of all input and output commitments.
	// This gives us a convenient way of verifying cut_through.
	fn inputs_outputs_committed(&self) -> Vec<Commitment> {
		let mut commits = self.inputs_committed();
		commits.extend_from_slice(self.outputs_committed().as_slice());
		commits.sort_unstable();
		commits
	}

	// Verify that no input is spending an output from the same block.
	// The inputs and outputs are not guaranteed to be sorted consistently once we support "commit only" inputs.
	// We need to allocate as we need to sort the commitments so we keep this very simple and just look
	// for duplicates across all input and output commitments.
	fn verify_cut_through(&self) -> Result<(), Error> {
		let commits = self.inputs_outputs_committed();
		for pair in commits.windows(2) {
			if pair[0] == pair[1] {
				return Err(Error::CutThrough);
			}
		}
		Ok(())
	}

	/// Verify we have no invalid outputs or kernels in the transaction
	/// due to invalid features.
	/// Specifically, a transaction cannot contain a coinbase output or a coinbase kernel.
	pub fn verify_features(&self) -> Result<(), Error> {
		self.verify_output_features()?;
		self.verify_kernel_features()?;
		Ok(())
	}

	// Verify we have no outputs tagged as COINBASE.
	fn verify_output_features(&self) -> Result<(), Error> {
		if self.outputs.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	// Verify we have no kernels tagged as COINBASE.
	fn verify_kernel_features(&self) -> Result<(), Error> {
		if self.kernels.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidKernelFeatures);
		}
		Ok(())
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification
	/// * kernel signature verification
	pub fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		self.verify_weight(weighting)?;
		self.verify_no_nrd_duplicates()?;
		self.verify_sorted()?;
		self.verify_cut_through()?;
		Ok(())
	}

	/// We only allow a maximum burn per tx of 100,000 BMWs. This is to ensure
	/// overflows do not occur.
	pub fn validate_max_burn(&self) -> Result<(), Error> {
		for kernel in self.kernels() {
			match kernel.features {
				KernelFeatures::Burn { amount, .. } => {
					if amount > 100_000_000_000_000 {
						return Err(Error::MaxBurnExceeded);
					}
				}
				_ => {}
			}
		}
		Ok(())
	}

	/// Identifiers w/ R&P'.
	pub fn identifiers(&self) -> Vec<OutputIdentifier> {
		self.outputs
			.iter()
			.map(|o| o.identifier.clone())
			.collect::<Vec<OutputIdentifier>>()
	}

	/// Validates all relevant parts of a transaction body. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		self.validate_max_burn()?;
		self.validate_read(weighting)?;

		// Find all the outputs that have not had their rangeproofs verified.
		let outputs = {
			let mut verifier = verifier.write();
			verifier.filter_rangeproof_unverified(&self.outputs)
		};

		// Now batch verify all those unverified rangeproofs
		if !outputs.is_empty() {
			let mut commits = vec![];
			let mut proofs = vec![];
			for x in &outputs {
				commits.push(x.commitment());
				proofs.push(x.proof);
			}
			Output::batch_verify_proofs(&commits, &proofs)?;
		}

		// Find all the kernels that have not yet been verified.
		let kernels = {
			let mut verifier = verifier.write();
			verifier.filter_kernel_sig_unverified(&self.kernels)
		};

		// Verify the unverified tx kernels.
		TxKernel::batch_sig_verify(&kernels)?;

		// Verify the unverified Identifiers.
		let identifiers = {
			let mut verifier = verifier.write();
			verifier.filter_r_sig_unverified(&self.identifiers())
		};

		OutputIdentifier::batch_sig_verify(&identifiers)?;

		// Cache the successful verification results for the new outputs and kernels.
		{
			let mut verifier = verifier.write();
			verifier.add_rangeproof_verified(outputs);
			verifier.add_kernel_sig_verified(kernels);
			verifier.add_r_sig_verified(identifiers);
		}
		Ok(())
	}
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBody,
}

impl DefaultHashable for Transaction {}

/// PartialEq
impl PartialEq for Transaction {
	fn eq(&self, tx: &Transaction) -> bool {
		self.body == tx.body && self.offset == tx.offset
	}
}

/// Implementation of Writeable for a fully blinded transaction, defines how to
/// write the transaction as binary.
impl Writeable for Transaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.offset.write(writer)?;
		self.body.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction, defines how to read a full
/// transaction from a binary stream.
impl Readable for Transaction {
	fn read<R: Reader>(reader: &mut R) -> Result<Transaction, ser::Error> {
		let offset = BlindingFactor::read(reader)?;
		let body = TransactionBody::read(reader)?;
		let tx = Transaction { offset, body };

		// Now "lightweight" validation of the tx.
		// Treat any validation issues as data corruption.
		// An example of this would be reading a tx
		// that exceeded the allowed number of inputs.
		tx.validate_read().map_err(|_| ser::Error::CorruptedData)?;

		Ok(tx)
	}
}

impl Committed for Transaction {
	fn inputs_committed(&self) -> Vec<Commitment> {
		self.body.inputs_committed()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.body.outputs_committed()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.body.kernels_committed()
	}
}

impl Default for Transaction {
	fn default() -> Transaction {
		Transaction::empty()
	}
}

impl Transaction {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> Transaction {
		Transaction {
			offset: BlindingFactor::zero(),
			body: Default::default(),
		}
	}

	/// Creates a new transaction initialized with
	/// the provided inputs, outputs, kernels
	pub fn new(inputs: Inputs, outputs: &[Output], kernels: &[TxKernel]) -> Transaction {
		// Initialize a new tx body and sort everything.
		let body =
			TransactionBody::init(inputs, outputs, kernels, false).expect("sorting, not verifying");

		Transaction {
			offset: BlindingFactor::zero(),
			body,
		}
	}

	/// Creates a new transaction using this transaction as a template
	/// and with the specified offset.
	pub fn with_offset(self, offset: BlindingFactor) -> Transaction {
		Transaction { offset, ..self }
	}

	/// Builds a new transaction with the provided inputs_with_wsig added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input_wsig(self, input: CommitWrapper) -> Transaction {
		Transaction {
			body: self.body.with_input_wsig(input),
			..self
		}
	}

	/// Builds a new transaction with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(self, input: Input) -> Transaction {
		Transaction {
			body: self.body.with_input(input),
			..self
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> Transaction {
		Transaction {
			body: self.body.with_output(output),
			..self
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> Transaction {
		Transaction {
			body: self.body.with_kernel(kernel),
			..self
		}
	}

	/// Builds a new transaction replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(self, kernel: TxKernel) -> Transaction {
		Transaction {
			body: self.body.replace_kernel(kernel),
			..self
		}
	}

	/// Get inputs
	pub fn inputs(&self) -> Inputs {
		self.body.inputs()
	}

	/// Get outputs
	pub fn outputs(&self) -> &[Output] {
		&self.body.outputs()
	}

	/// Get kernels
	pub fn kernels(&self) -> &[TxKernel] {
		&self.body.kernels()
	}

	/// Total fee for a transaction is the sum of fees of all kernels.
	pub fn fee(&self, height: u64) -> u64 {
		self.body.fee(height)
	}

	/// Shifted fee for a transaction is the sum of fees of all kernels shifted right by the maximum fee shift
	pub fn shifted_fee(&self, height: u64) -> u64 {
		self.body.shifted_fee(height)
	}

	/// aggregate fee_fields from all appropriate kernels in transaction into one
	pub fn aggregate_fee_fields(&self, height: u64) -> Result<FeeFields, Error> {
		self.body.aggregate_fee_fields(height)
	}

	/// Total overage across all kernels.
	pub fn overage(
		&self,
		height: u64,
		utxo_data: Option<Weak<RwLock<UtxoData>>>,
		amount: Option<u64>,
	) -> i64 {
		self.body.overage(height, utxo_data, amount)
	}

	/// Lock height of a transaction is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.body.lock_height()
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification (on the body)
	/// * kernel signature verification (on the body)
	/// * kernel sum verification
	pub fn validate_read(&self) -> Result<(), Error> {
		self.body.validate_read(Weighting::AsTransaction)?;
		self.body.verify_features()?;
		Ok(())
	}

	/// Validate each transaction's btc claims
	fn validate_btc_claims(&self, utxo_data: Option<Weak<RwLock<UtxoData>>>) -> Result<(), Error> {
		for kernel in self.kernels() {
			match kernel.features {
				KernelFeatures::BTCClaim { .. } => {
					kernel.validate_btcclaim(utxo_data.clone())?;
				}
				_ => {}
			}
		}
		Ok(())
	}

	/// Validates all relevant parts of a fully built transaction. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		height: u64,
		utxo_data: Option<Weak<RwLock<UtxoData>>>,
		amount: Option<u64>,
	) -> Result<(), Error> {
		self.body.verify_features()?;
		self.body.validate(weighting, verifier)?;
		self.validate_btc_claims(utxo_data.clone())?;
		self.verify_kernel_sums(self.overage(height, utxo_data, amount), self.offset.clone())?;
		Ok(())
	}

	/// Can be used to compare txs by their fee/weight ratio, aka feerate.
	/// Don't use these values for anything else though due to precision multiplier.
	pub fn fee_rate(&self, height: u64) -> u64 {
		self.fee(height) / self.weight() as u64
	}

	/// Calculate transaction weight
	pub fn weight(&self) -> u64 {
		self.body.weight()
	}

	/// Transaction minimum acceptable fee
	/// Enable from start now
	pub fn accept_fee(&self, _height: u64) -> u64 {
		self.weight() * global::get_accept_fee_base()
	}

	/// Old weight definition for pool acceptance
	pub fn old_weight_by_iok(num_inputs: u64, num_outputs: u64, num_kernels: u64) -> u64 {
		let body_weight = num_outputs
			.saturating_mul(4)
			.saturating_add(num_kernels)
			.saturating_sub(num_inputs);
		max(body_weight, 1)
	}

	/// Calculate transaction weight from transaction details
	pub fn weight_by_iok(num_inputs: u64, num_outputs: u64, num_kernels: u64) -> u64 {
		TransactionBody::weight_by_iok(num_inputs, num_outputs, num_kernels)
	}
}

/// Takes a slice of inputs and a slice of outputs and applies "cut-through"
/// eliminating any input/output pairs with input spending output.
/// Returns new slices with cut-through elements removed.
/// Also returns slices of the cut-through elements themselves.
/// Note: Takes slices of _anything_ that is AsRef<Commitment> for greater flexibility.
/// So we can cut_through inputs and outputs but we can also cut_through inputs and output identifiers.
/// Or we can get crazy and cut_through inputs with other inputs to identify intersection and difference etc.
///
/// Example:
/// Inputs: [A, B, C]
/// Outputs: [C, D, E]
/// Returns: ([A, B], [D, E], [C], [C]) # element C is cut-through
pub fn cut_through<'a, 'b, T, U>(
	inputs: &'a mut [T],
	outputs: &'b mut [U],
) -> Result<(&'a [T], &'b [U], &'a [T], &'b [U]), Error>
where
	T: AsRef<Commitment> + Ord,
	U: AsRef<Commitment> + Ord,
{
	// Make sure inputs and outputs are sorted consistently as we will iterate over both.
	inputs.sort_unstable_by_key(|x| *x.as_ref());
	outputs.sort_unstable_by_key(|x| *x.as_ref());

	let mut inputs_idx = 0;
	let mut outputs_idx = 0;
	let mut ncut = 0;
	while inputs_idx < inputs.len() && outputs_idx < outputs.len() {
		match inputs[inputs_idx]
			.as_ref()
			.cmp(&outputs[outputs_idx].as_ref())
		{
			Ordering::Less => {
				inputs.swap(inputs_idx - ncut, inputs_idx);
				inputs_idx += 1;
			}
			Ordering::Greater => {
				outputs.swap(outputs_idx - ncut, outputs_idx);
				outputs_idx += 1;
			}
			Ordering::Equal => {
				inputs_idx += 1;
				outputs_idx += 1;
				ncut += 1;
			}
		}
	}

	// Make sure we move any the remaining inputs into the slice to be returned.
	while inputs_idx < inputs.len() {
		inputs.swap(inputs_idx - ncut, inputs_idx);
		inputs_idx += 1;
	}

	// Make sure we move any the remaining outputs into the slice to be returned.
	while outputs_idx < outputs.len() {
		outputs.swap(outputs_idx - ncut, outputs_idx);
		outputs_idx += 1;
	}

	// Split inputs and outputs slices into non-cut-through and cut-through slices.
	let (inputs, inputs_cut) = inputs.split_at_mut(inputs.len() - ncut);
	let (outputs, outputs_cut) = outputs.split_at_mut(outputs.len() - ncut);

	// Resort all the new slices.
	inputs.sort_unstable();
	outputs.sort_unstable();
	inputs_cut.sort_unstable();
	outputs_cut.sort_unstable();

	// Check we have no duplicate inputs after cut-through.
	if inputs.windows(2).any(|pair| pair[0] == pair[1]) {
		return Err(Error::CutThrough);
	}

	// Check we have no duplicate outputs after cut-through.
	if outputs.windows(2).any(|pair| pair[0] == pair[1]) {
		return Err(Error::CutThrough);
	}

	Ok((inputs, outputs, inputs_cut, outputs_cut))
}

/// Aggregate a vec of txs into a multi-kernel tx with cut_through.
pub fn aggregate(txs: &[Transaction]) -> Result<Transaction, Error> {
	// convenience short-circuiting
	if txs.is_empty() {
		return Ok(Transaction::empty());
	} else if txs.len() == 1 {
		return Ok(txs[0].clone());
	}

	let (n_inputs, n_outputs, n_kernels) =
		txs.iter()
			.fold((0, 0, 0), |(inputs, outputs, kernels), tx| {
				(
					inputs + tx.inputs().len(),
					outputs + tx.outputs().len(),
					kernels + tx.kernels().len(),
				)
			});
	let mut inputs: Vec<CommitWrapper> = Vec::with_capacity(n_inputs);
	let mut outputs: Vec<Output> = Vec::with_capacity(n_outputs);
	let mut kernels: Vec<TxKernel> = Vec::with_capacity(n_kernels);

	// we will sum these together at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets: Vec<BlindingFactor> = Vec::with_capacity(txs.len());
	for tx in txs {
		// we will sum these later to give a single aggregate offset
		kernel_offsets.push(tx.offset.clone());

		let tx_inputs: Vec<_> = tx.inputs().into();
		inputs.extend_from_slice(&tx_inputs);
		outputs.extend_from_slice(tx.outputs());
		kernels.extend_from_slice(tx.kernels());
	}

	let (inputs, outputs, _, _) = cut_through(&mut inputs, &mut outputs)?;

	// now sum the kernel_offsets up to give us an aggregate offset for the
	// transaction
	let total_kernel_offset = committed::sum_kernel_offsets(kernel_offsets, vec![])?;

	// build a new aggregate tx from the following -
	//   * cut-through inputs
	//   * cut-through outputs
	//   * full set of tx kernels
	//   * sum of all kernel offsets
	// Note: We sort input/outputs/kernels when building the transaction body internally.
	let tx =
		Transaction::new(Inputs::from(inputs), outputs, &kernels).with_offset(total_kernel_offset);

	Ok(tx)
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple
/// transactions
pub fn deaggregate(mk_tx: Transaction, txs: &[Transaction]) -> Result<Transaction, Error> {
	let mut inputs: Vec<CommitWrapper> = vec![];
	let mut outputs: Vec<Output> = vec![];
	let mut kernels: Vec<TxKernel> = vec![];

	// we will subtract these at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets = vec![];

	let tx = aggregate(txs)?;

	let mk_inputs: Vec<_> = mk_tx.inputs().into();
	for mk_input in mk_inputs {
		let tx_inputs: Vec<_> = tx.inputs().into();
		if !tx_inputs.contains(&mk_input) && !inputs.contains(&mk_input) {
			inputs.push(mk_input);
		}
	}
	for mk_output in mk_tx.outputs() {
		if !tx.outputs().contains(&mk_output) && !outputs.contains(mk_output) {
			outputs.push(*mk_output);
		}
	}
	for mk_kernel in mk_tx.kernels() {
		if !tx.kernels().contains(&mk_kernel) && !kernels.contains(mk_kernel) {
			kernels.push(mk_kernel.clone());
		}
	}

	kernel_offsets.push(tx.offset);

	// now compute the total kernel offset
	let total_kernel_offset = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let positive_key = vec![mk_tx.offset]
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key(&secp).ok())
			.collect::<Vec<_>>();
		let negative_keys = kernel_offsets
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key(&secp).ok())
			.collect::<Vec<_>>();

		if positive_key.is_empty() && negative_keys.is_empty() {
			BlindingFactor::zero()
		} else {
			let sum = secp.blind_sum(positive_key, negative_keys)?;
			BlindingFactor::from_secret_key(sum)
		}
	};

	// Sorting them lexicographically
	inputs.sort_unstable();
	outputs.sort_unstable();
	kernels.sort_unstable();

	// Build a new tx from the above data.
	Ok(
		Transaction::new(Inputs::from(inputs.as_slice()), &outputs, &kernels)
			.with_offset(total_kernel_offset),
	)
}

/// A transaction input.
///
/// Primarily a reference to an output being spent by the transaction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Input {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// The signature for the spending output P'. (NIT)
	#[serde(with = "secp_ser::sig_serde")]
	pub sig: SecpSignature,
}

impl DefaultHashable for Input {}
hashable_ord!(Input);

impl AsRef<Commitment> for Input {
	fn as_ref(&self) -> &Commitment {
		&self.commit
	}
}

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for Input {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		self.sig.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for Input {
	fn read<R: Reader>(reader: &mut R) -> Result<Input, ser::Error> {
		let features = OutputFeatures::read(reader)?;
		let commit = Commitment::read(reader)?;
		let sig = SecpSignature::read(reader)?;
		Ok(Input::new(features, commit, sig))
	}
}

/// The input for a transaction, which spends a pre-existing unspent output.
/// The input commitment is a reproduction of the commitment of the output
/// being spent. Input must also provide the original output features and the
/// hash of the block the output originated from.
impl Input {
	/// Build a new input from the data required to identify and verify an
	/// output being spent.
	pub fn new(features: OutputFeatures, commit: Commitment, sig: SecpSignature) -> Input {
		Input {
			features,
			commit,
			sig,
		}
	}

	/// The input commitment which _partially_ identifies the output being
	/// spent. In the presence of a fork we need additional info to uniquely
	/// identify the output. Specifically the block hash (to correctly
	/// calculate lock_height for coinbase outputs).
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase input?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain input?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}
}

/// We need to wrap commitments so they can be sorted with hashable_ord.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CommitWrapper {
	/// The commitment
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// The signature for the spending output P'. (NIT)
	#[serde(with = "secp_ser::sig_serde")]
	pub sig: SecpSignature,
}

impl DefaultHashable for CommitWrapper {}
hashable_ord!(CommitWrapper);

impl From<Input> for CommitWrapper {
	fn from(input: Input) -> Self {
		CommitWrapper {
			commit: input.commitment(),
			sig: input.sig,
		}
	}
}

impl From<&Input> for CommitWrapper {
	fn from(input: &Input) -> Self {
		CommitWrapper {
			commit: input.commitment(),
			sig: input.sig,
		}
	}
}

impl AsRef<Commitment> for CommitWrapper {
	fn as_ref(&self) -> &Commitment {
		&self.commit
	}
}

impl Readable for CommitWrapper {
	fn read<R: Reader>(reader: &mut R) -> Result<CommitWrapper, ser::Error> {
		let commit = Commitment::read(reader)?;
		let sig = secp::Signature::read(reader)?;
		Ok(CommitWrapper { commit, sig })
	}
}

impl Writeable for CommitWrapper {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.commit.write(writer)?;
		self.sig.write(writer)?;
		Ok(())
	}
}

/*
impl From<Inputs> for Vec<CommitWrapper> {
	fn from(inputs: Inputs) -> Self {
		match inputs {
			Inputs::CommitOnly(inputs) => inputs,
		}
	}
}
*/

/*
impl From<&Inputs> for Vec<CommitWrapper> {
	fn from(inputs: &Inputs) -> Self {
		match inputs {
			Inputs::CommitOnly(inputs) => inputs.clone(),
		}
	}
}
*/

impl CommitWrapper {
	/// Wrapped commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(
		accomplished_inputs_with_sig: &[(OutputIdentifier, Hash, CommitWrapper)],
	) -> Result<(), Error> {
		let len = accomplished_inputs_with_sig.len();
		let mut sigs = Vec::with_capacity(len);
		let mut pubkeys = Vec::with_capacity(len);
		let mut msgs = Vec::with_capacity(len);

		for (rnp, h, input) in accomplished_inputs_with_sig {
			sigs.push(input.sig.clone());
			if rnp.commitment() == input.commit {
				pubkeys.push(rnp.onetime_pubkey.clone());
				msgs.push(rnp.input_sig_msg(*h));
			} else {
				return Err(Error::IncorrectSignature);
			}
		}

		let secp = static_secp_instance();
		let secp = secp.lock();

		if !aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}
}
/// Wrapper around a vec of inputs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Inputs(pub Vec<CommitWrapper>);

impl From<&Inputs> for Vec<CommitWrapper> {
	fn from(inputs: &Inputs) -> Vec<CommitWrapper> {
		let mut ret = vec![];
		for input in &inputs.0 {
			ret.push(*input);
		}
		ret.sort_unstable();
		ret.to_vec()
	}
}

impl From<Inputs> for Vec<CommitWrapper> {
	fn from(inputs: Inputs) -> Vec<CommitWrapper> {
		let mut ret = vec![];
		for input in inputs {
			ret.push(input);
		}
		ret.sort_unstable();
		ret
	}
}

impl From<&[Input]> for Inputs {
	fn from(inputs: &[Input]) -> Self {
		let mut wrappers = vec![];
		for input in inputs {
			wrappers.push(CommitWrapper {
				commit: input.commitment(),
				sig: input.sig,
			});
		}
		let mut ret = Inputs(wrappers);
		ret.sort_unstable();
		ret
	}
}

impl From<&[CommitWrapper]> for Inputs {
	fn from(commits: &[CommitWrapper]) -> Self {
		let mut ret = Inputs(commits.to_vec());
		ret.sort_unstable();
		ret
	}
}

impl Default for Inputs {
	fn default() -> Self {
		Inputs(vec![])
	}
}

impl Writeable for Inputs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// Nothing to write so we are done.
		if self.is_empty() {
			return Ok(());
		}
		self.0.write(writer)?;
		Ok(())
	}
}

impl IntoIterator for Inputs {
	type Item = CommitWrapper;
	type IntoIter = std::vec::IntoIter<Self::Item>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl Inputs {
	/// Number of inputs.
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Empty inputs?
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Verify inputs are sorted and unique.
	fn verify_sorted_and_unique(&self) -> Result<(), ser::Error> {
		self.0.verify_sorted_and_unique()
	}

	/// Sort the inputs.
	fn sort_unstable(&mut self) {
		self.0.sort_unstable();
	}

	/// add an item
	fn add(&mut self, elem: CommitWrapper) {
		self.0.push(elem);
		self.sort_unstable();
	}

	/// For debug purposes only. Do not rely on this for anything.
	pub fn version_str(&self) -> &str {
		"v3"
	}

	/// build a hashmap from the commit -> signatures for reconstructing from outputidentifiers
	pub fn build_map(&self) -> Result<HashMap<Commitment, SecpSignature>, Error> {
		let mut sig_map = HashMap::new();
		for input in self.0.clone().into_iter().enumerate() {
			sig_map.insert(input.1.commit, input.1.sig);
		}
		Ok(sig_map)
	}

	/// convert from &[OutputIdentifier], Map<commit, SecpSignature> -> Inputs
	pub fn from_output_identifiers(
		output_identifiers: &[OutputIdentifier],
		sig_map: HashMap<Commitment, SecpSignature>,
	) -> Result<Inputs, Error> {
		let mut inputs_with_sigs = Vec::new();
		for input in output_identifiers {
			let commit = input.commit;
			let sig = *sig_map
				.get(&commit)
				.unwrap_or(&secp::Signature::from_raw_data(&[0; 64]).unwrap());
			let features = input.features;
			inputs_with_sigs.push(Input {
				commit,
				sig,
				features,
			});
		}
		let mut inputs_with_sigs_commit_wrappers = vec![];
		for input in inputs_with_sigs {
			inputs_with_sigs_commit_wrappers.push(CommitWrapper {
				commit: input.commit,
				sig: input.sig,
			});
		}
		inputs_with_sigs_commit_wrappers.sort_unstable();
		Ok(Inputs(inputs_with_sigs_commit_wrappers))
	}
}

// Enum of various supported kernel "features".
enum_from_primitive! {
	/// Various flavors of tx kernel.
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	#[repr(u8)]
	pub enum OutputFeatures {
		/// Plain output (the default for Grin txs).
		Plain = 0,
		/// A coinbase output.
		Coinbase = 1,
	}
}

impl DefaultHashable for OutputFeatures {}

impl Writeable for OutputFeatures {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(*self as u8)?;
		Ok(())
	}
}

impl Readable for OutputFeatures {
	fn read<R: Reader>(reader: &mut R) -> Result<OutputFeatures, ser::Error> {
		let features =
			OutputFeatures::from_u8(reader.read_u8()?).ok_or(ser::Error::CorruptedData)?;
		Ok(features)
	}
}

/// Output for a transaction, defining the new ownership of coins that are being
/// transferred. The commitment is a blinded value for the output while the
/// range proof guarantees the commitment includes a positive value without
/// overflow and the ownership of the private key.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Output {
	/// Output identifier (features and commitment).
	#[serde(flatten)]
	pub identifier: OutputIdentifier,
	/// Rangeproof associated with the commitment.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

impl Ord for Output {
	fn cmp(&self, other: &Self) -> Ordering {
		self.identifier.cmp(&other.identifier)
	}
}

impl PartialOrd for Output {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl PartialEq for Output {
	fn eq(&self, other: &Self) -> bool {
		self.identifier == other.identifier
	}
}

impl Eq for Output {}

impl AsRef<Commitment> for Output {
	fn as_ref(&self) -> &Commitment {
		&self.identifier.commit
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
impl Writeable for Output {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.identifier.write(writer)?;
		self.proof.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for Output {
	fn read<R: Reader>(reader: &mut R) -> Result<Output, ser::Error> {
		Ok(Output {
			identifier: OutputIdentifier::read(reader)?,
			proof: RangeProof::read(reader)?,
		})
	}
}

impl OutputFeatures {
	/// Is this a coinbase output?
	pub fn is_coinbase(self) -> bool {
		self == OutputFeatures::Coinbase
	}

	/// Is this a plain output?
	pub fn is_plain(self) -> bool {
		self == OutputFeatures::Plain
	}
}

impl Output {
	/// Create a new output with the provided features, commitment and rangeproof.
	pub fn new(
		features: OutputFeatures,
		commit: Commitment,
		proof: RangeProof,
		r_sig: SecpSignature,
		view_tag: u8,
		nonce: PublicKey,
		onetime_pubkey: PublicKey,
	) -> Output {
		Output {
			identifier: OutputIdentifier::new(
				features,
				&commit,
				r_sig,
				view_tag,
				nonce,
				onetime_pubkey,
			),
			proof,
		}
	}

	/// Output identifier.
	pub fn identifier(&self) -> OutputIdentifier {
		self.identifier
	}

	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.identifier.commitment()
	}

	/// Output features.
	pub fn features(&self) -> OutputFeatures {
		self.identifier.features
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.identifier.is_coinbase()
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		self.identifier.is_plain()
	}

	/// Range proof for the output
	pub fn proof(&self) -> RangeProof {
		self.proof
	}

	/// Get range proof as byte slice
	pub fn proof_bytes(&self) -> &[u8] {
		&self.proof.proof[..]
	}

	/// Validates the range proof using the commitment
	pub fn verify_proof(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof(self.commitment(), self.proof, None)?;
		Ok(())
	}

	/// Batch validates the range proofs using the commitments
	pub fn batch_verify_proofs(commits: &[Commitment], proofs: &[RangeProof]) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof_multi(commits.to_vec(), proofs.to_vec(), None)?;
		Ok(())
	}
}

impl DefaultHashable for Output {}

impl AsRef<OutputIdentifier> for Output {
	fn as_ref(&self) -> &OutputIdentifier {
		&self.identifier
	}
}

/// An output_identifier can be build from either an input _or_ an output and
/// contains everything we need to uniquely identify an output being spent.
/// Needed because it is not sufficient to pass a commitment around.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct OutputIdentifier {
	/// Output features (coinbase vs. regular transaction output)
	/// We need to include this when hashing to ensure coinbase maturity can be
	/// enforced.
	pub features: OutputFeatures,
	/// Output commitment
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,

	/// The rest of this are the NIT related fields

	/// Public nonce R for generating Ephemeral key.
	#[serde(with = "secp_ser::pubkey_serde")]
	pub nonce: PublicKey,
	/// R signature as the spending coin ownership proof by equation (2) of https://eprint.iacr.org/2020/1064.pdf.
	#[serde(with = "secp_ser::sig_serde")]
	pub r_sig: SecpSignature,
	/// One-time public key P' which is calculated by H(A')*G+B
	#[serde(with = "secp_ser::pubkey_serde")]
	pub onetime_pubkey: PublicKey,
	/// The "view tag" of a Stealth Address, i.e. the first byte of the shared secret.
	/// For Stealth Address (A,B): "view tag" = `Hash(a*R) === Hash(r*A)`.
	pub view_tag: u8,
}

impl DefaultHashable for OutputIdentifier {}
hashable_ord!(OutputIdentifier);

impl AsRef<Commitment> for OutputIdentifier {
	fn as_ref(&self) -> &Commitment {
		&self.commit
	}
}

impl OutputIdentifier {
	/// Build a new output_identifier.
	pub fn new(
		features: OutputFeatures,
		commit: &Commitment,
		r_sig: SecpSignature,
		view_tag: u8,
		nonce: PublicKey,
		onetime_pubkey: PublicKey,
	) -> OutputIdentifier {
		OutputIdentifier {
			features,
			commit: *commit,
			r_sig,
			nonce,
			onetime_pubkey,
			view_tag,
		}
	}

	/// Our commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Converts this identifier to a full output, provided a RangeProof
	pub fn into_output(self, proof: RangeProof) -> Output {
		Output {
			identifier: self,
			proof,
		}
	}

	/// Get signing message for Input P'-signature.
	/// Msg = Hash(OutputFeatures || commit || view_tag || R || H(index | Rangeproof)).
	/// Note:
	///   - Message include the hash of rangeproof which has a proof message with a timestamp, to kill the replay attack.
	///   - Instead of using rangeproof hash, we use the rangeproof MMR leaf node hash which always prepends the node's position in the MMR,
	///     this helps to avoid the real hash computation and enables a directly reading the MMR leaf node hash.
	pub fn input_sig_msg(&self, rp_hash: Hash) -> secp::Message {
		let secp = util::secp::Secp256k1::with_caps(ContextFlag::Full);
		secp::Message::from_slice(
			(
				self,
				self.view_tag,
				self.nonce.serialize_vec(&secp, true).as_ref().to_vec(),
				rp_hash,
			)
				.hash()
				.to_vec()
				.as_slice(),
		)
		.unwrap()
	}

	/// Get signing message for Output R signature.
	/// Msg = Hash(OutputFeatures || commit || view_tag || P').
	pub fn output_rr_sig_msg(&self) -> secp::Message {
		let serialized_onetime_pubkey = {
			let secp = static_secp_instance();
			let secp = secp.lock();
			self.onetime_pubkey
				.serialize_vec(&secp, true)
				.as_ref()
				.to_vec()
		};
		secp::Message::from_slice(
			(
				self.features,
				self.commit,
				self.view_tag,
				serialized_onetime_pubkey,
			)
				.hash()
				.to_vec()
				.as_slice(),
		)
		.unwrap()
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(outputs: &[OutputIdentifier]) -> Result<(), Error> {
		let len = outputs.len();
		let mut sigs = Vec::with_capacity(len);
		let mut pubkeys = Vec::with_capacity(len);
		let mut msgs = Vec::with_capacity(len);

		for identifier in outputs {
			sigs.push(identifier.r_sig.clone());
			pubkeys.push(identifier.nonce.clone());
			msgs.push(identifier.output_rr_sig_msg());
		}

		let secp = static_secp_instance();
		let secp = secp.lock();
		if !aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}
}

impl DefaultHashable for Commitment {}

impl ToHex for OutputIdentifier {
	fn to_hex(&self) -> String {
		format!("{:b}{}", self.features as u8, self.commit.to_hex())
	}
}

impl Writeable for OutputIdentifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		self.r_sig.write(writer)?;
		self.nonce.write(writer)?;
		self.onetime_pubkey.write(writer)?;
		self.view_tag.write(writer)?;
		Ok(())
	}
}

impl Readable for OutputIdentifier {
	fn read<R: Reader>(reader: &mut R) -> Result<OutputIdentifier, ser::Error> {
		Ok(OutputIdentifier {
			features: OutputFeatures::read(reader)?,
			commit: Commitment::read(reader)?,
			r_sig: secp::Signature::read(reader)?,
			nonce: PublicKey::read(reader)?,
			onetime_pubkey: PublicKey::read(reader)?,
			view_tag: reader.read_u8()?,
		})
	}
}

impl PMMRable for OutputIdentifier {
	type E = Self;

	fn as_elmt(&self) -> OutputIdentifier {
		*self
	}

	fn elmt_size() -> Option<u16> {
		Some(
			(2 + secp::constants::PEDERSEN_COMMITMENT_SIZE
				+ secp::constants::COMPRESSED_PUBLIC_KEY_SIZE * 2
				+ secp::constants::COMPACT_SIGNATURE_SIZE)
				.try_into()
				.unwrap(),
		)
	}
}

impl AsRef<OutputIdentifier> for OutputIdentifier {
	fn as_ref(&self) -> &OutputIdentifier {
		self
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hash;
	use crate::core::id::{ShortId, ShortIdentifiable};
	use crate::ser::ProtocolVersion;
	use keychain::{ExtKeychain, Keychain, SwitchCommitmentType};

	#[test]
	fn test_plain_kernel_ser_deser() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		// just some bytes for testing ser/deser
		let sig = secp::Signature::from_raw_data(&[0; 64]).unwrap();

		let kernel = TxKernel {
			features: KernelFeatures::Plain { fee: 10.into() },
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize(&mut &vec[..], version).unwrap();
			assert_eq!(kernel2.features, KernelFeatures::Plain { fee: 10.into() });
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(kernel2.features, KernelFeatures::Plain { fee: 10.into() });
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn test_height_locked_kernel_ser_deser() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		// just some bytes for testing ser/deser
		let sig = secp::Signature::from_raw_data(&[0; 64]).unwrap();

		// now check a kernel with lock_height serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::HeightLocked {
				fee: 10.into(),
				lock_height: 100,
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize(&mut &vec[..], version).unwrap();
			assert_eq!(kernel.features, kernel2.features);
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(kernel.features, kernel2.features);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn test_nrd_kernel_ser_deser() {
		global::set_local_nrd_enabled(true);

		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		// just some bytes for testing ser/deser
		let sig = secp::Signature::from_raw_data(&[0; 64]).unwrap();

		// now check an NRD kernel will serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::NoRecentDuplicate {
				fee: 10.into(),
				relative_height: NRDRelativeHeight(100),
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize(&mut &vec[..], version).unwrap();
			assert_eq!(kernel.features, kernel2.features);
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(kernel.features, kernel2.features);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn test_btcclaim_kernel_ser_deser() {
		global::set_local_nrd_enabled(true);

		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		// just some bytes for testing ser/deser
		let sig = secp::Signature::from_raw_data(&[0; 64]).unwrap();

		// just some bytes for testing ser/deser
		let mut signature = [0 as u8; 65];
		for i in 0..65 {
			signature[i] = i as u8;
		}

		// now check a BTCClaim kernel will serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::BTCClaim {
				fee: 10.into(),
				index: 1,
				btc_signatures: vec![BTCSignature { signature }],
				redeem_script: None,
				address_type: 0, // does not matter for non redeem script
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize(&mut &vec[..], version).unwrap();

			assert_eq!(kernel.features, kernel2.features);
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(kernel.features, kernel2.features);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn nrd_kernel_verify_sig() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 10.into(),
			relative_height: NRDRelativeHeight(100),
		});

		// Construct the message to be signed.
		let msg = kernel.msg_to_sign().unwrap();

		let excess = keychain
			.commit(0, &key_id, SwitchCommitmentType::Regular)
			.unwrap();
		let skey = keychain
			.derive_key(0, &key_id, SwitchCommitmentType::Regular)
			.unwrap();
		let pubkey = excess.to_pubkey(&keychain.secp()).unwrap();

		let excess_sig =
			aggsig::sign_single(&keychain.secp(), &msg, &skey, None, Some(&pubkey)).unwrap();

		kernel.excess = excess;
		kernel.excess_sig = excess_sig;

		// Check the signature verifies.
		assert_eq!(kernel.verify(), Ok(()));

		// Modify the fee and check signature no longer verifies.
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: 9.into(),
			relative_height: NRDRelativeHeight(100),
		};
		assert_eq!(kernel.verify(), Err(Error::IncorrectSignature));

		// Modify the relative_height and check signature no longer verifies.
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: 10.into(),
			relative_height: NRDRelativeHeight(101),
		};
		assert_eq!(kernel.verify(), Err(Error::IncorrectSignature));

		// Swap the features out for something different and check signature no longer verifies.
		kernel.features = KernelFeatures::Plain { fee: 10.into() };
		assert_eq!(kernel.verify(), Err(Error::IncorrectSignature));

		// Check signature verifies if we use the original features.
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: 10.into(),
			relative_height: NRDRelativeHeight(100),
		};
		assert_eq!(kernel.verify(), Ok(()));
	}

	#[test]
	fn commit_consistency() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let commit = keychain
			.commit(1003, &key_id, SwitchCommitmentType::Regular)
			.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let commit_2 = keychain
			.commit(1003, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		assert!(commit == commit_2);
	}

	#[test]
	fn input_short_id() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		let input = Input {
			features: OutputFeatures::Plain,
			commit,
			sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		};

		let block_hash =
			Hash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();

		let nonce = 0;

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("0a454aaa6ca3").unwrap());

		// now generate the short_id for a *very* similar output (single feature flag
		// different) and check it generates a different short_id
		let input = Input {
			features: OutputFeatures::Coinbase,
			commit,
			sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		};

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("0ea71cba2a25").unwrap());
	}

	#[test]
	fn kernel_features_serialization() -> Result<(), Error> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(0u8, 10u64, 0u64))?;
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..])?;
		assert_eq!(features, KernelFeatures::Plain { fee: 10.into() });

		let mut vec = vec![];
		ser::serialize_default(
			&mut vec,
			&(1u8, 0u64, 0u64, NotarizationData { data: [0; 40] }),
		)?;
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..])?;
		assert_eq!(
			features,
			KernelFeatures::Coinbase {
				notarization_data: NotarizationData { data: [0; 40] }
			}
		);

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(2u8, 10u64, 100u64))?;
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..])?;
		assert_eq!(
			features,
			KernelFeatures::HeightLocked {
				fee: 10.into(),
				lock_height: 100
			}
		);

		// NRD kernel support not enabled by default.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(3u8, 10u64, 100u16)).expect("serialized failed");
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));

		// Additional kernel features unsupported.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(6u8)).expect("serialized failed");
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));

		Ok(())
	}

	#[test]
	fn kernel_features_serialization_nrd_enabled() -> Result<(), Error> {
		global::set_local_nrd_enabled(true);

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(3u8, 10u64, 100u16))?;
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..])?;
		assert_eq!(
			features,
			KernelFeatures::NoRecentDuplicate {
				fee: 10.into(),
				relative_height: NRDRelativeHeight(100)
			}
		);

		// NRD with relative height 0 is invalid.
		vec.clear();
		ser::serialize_default(&mut vec, &(3u8, 10u64, 0u16))?;
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));

		// NRD with relative height WEEK_HEIGHT+1 is invalid.
		vec.clear();
		let invalid_height = consensus::WEEK_HEIGHT + 1;
		ser::serialize_default(&mut vec, &(3u8, 10u64, invalid_height as u16))?;
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));

		// Kernel variant 6 (and above) is invalid.
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(6u8))?;
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));

		Ok(())
	}
}
