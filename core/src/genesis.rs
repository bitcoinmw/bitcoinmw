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

//! Definition of the genesis block. Placeholder for now.

// required for genesis replacement
//! #![allow(unused_imports)]

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]

use crate::core;
use crate::core::hash::Hash;
use crate::pow::{Difficulty, Proof, ProofOfWork};
use chrono::prelude::{TimeZone, Utc};
use keychain::BlindingFactor;

/// Genesis block definition for development networks. The proof of work size
/// is small enough to mine it on the fly, so it does not contain its own
/// proof of work solution. Can also be easily mutated for different tests.
pub fn genesis_dev() -> core::Block {
	core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(1997, 8, 4).and_hms(0, 0, 0),
		pow: ProofOfWork {
			nonce: 0,
			..Default::default()
		},
		..Default::default()
	})
}

/// Testnet genesis block
pub fn genesis_test() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2021, 1, 6).and_hms(0, 0, 0),
		prev_root: Hash::from_hex(
			"0000000000000000000c8f2f3253e94727703005d94270c2a2aa212f40666270",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 0,
		kernel_mmr_size: 0,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(1),
			secondary_scaling: 1,
			nonce: 75,
			proof: Proof {
				nonces: vec![
					48347504, 67134428, 75722088, 79240947, 82862409, 87433899, 92873255, 95497143,
					118432168, 137071433, 141694041, 161156668, 181501546, 184555848, 185792957,
					193299542, 202348259, 202415433, 249978445, 268569446, 276503285, 286237331,
					334449556, 336762509, 344508223, 350032876, 355598258, 363379787, 391496323,
					418787242, 428750134, 437143914, 473706964, 475682963, 480155566, 485504951,
					485521698, 486567329, 502266120, 521250247, 525919876, 528910220,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	gen.without_reward()
}

/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2021, 1, 6).and_hms(18, 0, 0),
		prev_root: Hash::from_hex(
			"0000000000000000000cb56a4918e648782e60ca5c3f560c65d22bf40c8d7787",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 0,
		kernel_mmr_size: 0,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(1),
			secondary_scaling: 1,
			nonce: 15,
			proof: Proof {
				nonces: vec![
					38146989, 40088496, 42636499, 54467064, 69944400, 90085981, 94957214,
					138529088, 151045920, 156132376, 177016659, 187816286, 188038909, 189110084,
					222129499, 237540381, 241773656, 270922207, 270947672, 293317253, 297524595,
					306627310, 350234611, 385352545, 403202182, 435399433, 440645501, 447803457,
					451088904, 462677742, 463199224, 467887333, 483890280, 488512511, 492243269,
					498769914, 501380847, 505906282, 517503687, 526076690, 534053400, 534496203,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});

	gen.without_reward()
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hashed;
	use crate::global;
	use crate::ser::{self, ProtocolVersion};
	use util::ToHex;

	#[test]
	fn testnet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Testnet);
		let gen_hash = genesis_test().hash();
		println!("testnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_test(), ProtocolVersion(1)).unwrap();
		println!("testnet genesis full hash: {}\n", gen_bin.hash().to_hex());

		assert_eq!(
			gen_hash.to_hex(),
			"3e0d959390726260653737cafd4a1935cf37d3ce881b07039265ee29295e9a58"
		);

		assert_eq!(
			gen_bin.hash().to_hex(),
			"cbdd20d64db042ea2f9b7b58b3b1dd0d43e9e77aac3e239af1e436616706e77a"
		);
	}

	#[test]
	fn mainnet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let gen_hash = genesis_main().hash();
		println!("mainnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_main(), ProtocolVersion(1)).unwrap();
		println!("mainnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"a4f86ad9c72ed4fc4f9f5989fb85a6a404e6d606ccfa1072de84a9708984faa3"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"0cf3e2bf323d2eeea4fe7e9f029108e0a8998fe19931bce71b49c6122733af29"
		);
	}
}
