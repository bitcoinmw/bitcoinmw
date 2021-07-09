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

//! Errors for the core crate.

use crate::core::committed;
use crate::ser;
use failure::{Context, Fail};
use util::secp;

/// Error definition
#[derive(Debug)]
pub struct Error {
	/// The error kind for this error
	pub inner: Context<ErrorKind>,
}

/// Kinds of errors for the core mod
#[derive(Debug, Fail)]
pub enum ErrorKind {
	/// Underlying Secp256k1 error (signature validation or invalid public key
	/// typically)
	#[fail(display = "Secp Error: '{:?}'", _0)]
	Secp(secp::Error),
	/// Underlying keychain related error
	#[fail(display = "Keychain Error: '{:?}'", _0)]
	Keychain(keychain::Error),
	/// The sum of output minus input commitments does not
	/// match the sum of kernel commitments
	#[fail(display = "Kernel mismatch sum")]
	KernelSumMismatch,
	/// Restrict tx total weight.
	#[fail(display = "Too Heavy")]
	TooHeavy,
	/// Error originating from an invalid lock-height
	#[fail(display = "Lock height: '{}'", _0)]
	LockHeight(u64),
	/// Range proof validation error
	#[fail(display = "RangeProof")]
	RangeProof,
	/// Error originating from an invalid Merkle proof
	#[fail(display = "RangeProof")]
	MerkleProof,
	/// Returns if the value hidden within the a RangeProof message isn't
	/// repeated 3 times, indicating it's incorrect
	#[fail(display = "InvalidProofMessage")]
	InvalidProofMessage,
	/// Error when verifying kernel sums via committed trait.
	#[fail(display = "Committed error: '{:?}'", _0)]
	Committed(committed::Error),
	/// Validation error relating to cut-through (tx is spending its own
	/// output).
	#[fail(display = "CutThrough")]
	CutThrough,
	/// Validation error relating to output features.
	/// It is invalid for a transaction to contain a coinbase output, for example.
	#[fail(display = "InvalidOutputFeatures")]
	InvalidOutputFeatures,
	/// Validation error relating to kernel features.
	/// It is invalid for a transaction to contain a coinbase kernel, for example.
	#[fail(display = "InvalidKernelFeatures")]
	InvalidKernelFeatures,
	/// There are more than one notary kernels in this txn.
	#[fail(display = "MultipleNotaryKernels")]
	MultipleNotaryKernelFeatures,
	/// Maximum burn of 100,000 BMWs is exceeded.
	#[fail(display = "MaxBurnExceeded")]
	MaxBurnExceeded,
	/// RecoveryByte Not found for this BTCKernel.
	#[fail(display = "RecoveryByteNotFound")]
	RecoveryByteNotFound,
	/// feeshift is limited to 4 bits and fee must be positive and fit in 40 bits.
	#[fail(display = "Invalid fee fields")]
	InvalidFeeFields,
	/// NRD kernel relative height is limited to 1 week duration and must be greater than 0.
	#[fail(display = "InvalidNrdRelativeHeight")]
	InvalidNRDRelativeHeight,
	/// Signature verification error.
	#[fail(display = "IncorrectSignature")]
	IncorrectSignature,
	/// Underlying serialization error.
	#[fail(display = "Serialization Error: {:?}", _0)]
	Serialization(ser::Error),
	/// UtxoData error
	#[fail(display = "Utxo Data Error: {}", _0)]
	UtxoDataError(String),
	/// The type of Kernel Features was not expected here.
	#[fail(display = "UnexpectedKernelFeaturesType")]
	UnexpectedKernelFeaturesType,
	/// The BTCSignature was invalid
	#[fail(display = "InvalidBTCSignature")]
	InvalidBTCSignature,
	/// Redeem Script is not found in the claim db
	#[fail(display = "InvalidRedeemScript")]
	InvalidRedeemScript,
	/// Invalid BTC Claim
	#[fail(display = "InvalidBTCClaim")]
	InvalidBTCClaim,
	/// No BTC Signature
	#[fail(display = "NoSignature")]
	NoSignature,
	/// Too Many Keys
	#[fail(display = "TooManyKeys")]
	TooManyKeys,
	/// The btc address was invalid
	#[fail(display = "InvalidBTCAddress")]
	InvalidBTCAddress,
	/// No utxo_data
	#[fail(display = "NoUtxoData")]
	NoUtxoData,
	/// Invalid witness address
	#[fail(display = "InvalidWitnessAddress: {}", _0)]
	InvalidWitnessAddress(String),
	/// Other
	#[fail(display = "Other: {}", _0)]
	Other(String),
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
			inner: Context::new(ErrorKind::Other(error.to_string())),
		}
	}
}

impl From<ser::Error> for Error {
	fn from(e: ser::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Serialization(e).into()),
		}
	}
}

impl From<bmw_utxo::error::Error> for Error {
	fn from(e: bmw_utxo::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::UtxoDataError(format!("{:?}", e)).into()),
		}
	}
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Secp(e).into()),
		}
	}
}

impl From<bitcoin::util::address::Error> for Error {
	fn from(e: bitcoin::util::address::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InvalidWitnessAddress(e.to_string()).into()),
		}
	}
}

impl From<keychain::Error> for Error {
	fn from(e: keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Keychain(e).into()),
		}
	}
}

impl From<committed::Error> for Error {
	fn from(e: committed::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Committed(e).into()),
		}
	}
}
