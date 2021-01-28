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
use util;
use util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
use util::secp::pedersen::{Commitment, RangeProof};
use util::secp::Signature;

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
		timestamp: Utc.ymd(2020, 1, 6).and_hms(0, 0, 0),
		prev_root: Hash::from_hex(
			"00000000000000000017ff4903ef366c8f62e3151ba74e41b8332a126542f538",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"73b5e0a05ea9e1e4e33b8f1c723bc5c10d17f07042c2af7644f4dbb61f4bc556",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"667a3ba22f237a875f67c9933037c8564097fa57a3e75be507916de28fc0da26",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"cfdddfe2d938d0026f8b1304442655bbdddde175ff45ddf44cb03bcb0071a72d",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			secondary_scaling: 1856,
			nonce: 23,
			proof: Proof {
				nonces: vec![
					16994232, 22975978, 32664019, 44016212, 50238216, 57272481, 85779161,
					124272202, 125203242, 133907662, 140522149, 145870823, 147481297, 164952795,
					177186722, 183382201, 197418356, 211393794, 239282197, 239323031, 250757611,
					281414565, 305112109, 308151499, 357235186, 374041407, 389924708, 390768911,
					401322239, 401886855, 406986280, 416797005, 418935317, 429007407, 439527429,
					484809502, 486257104, 495589543, 495892390, 525019296, 529899691, 531685572,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex("08df2f1d996cee37715d9ac0a0f3b13aae508d1101945acb8044954aee30960be9")
				.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			25, 176, 52, 246, 172, 1, 12, 220, 247, 111, 73, 101, 13, 16, 157, 130, 110, 196, 123,
			217, 246, 137, 45, 110, 106, 186, 0, 151, 255, 193, 233, 178, 103, 26, 210, 215, 200,
			89, 146, 188, 9, 161, 28, 212, 227, 143, 82, 54, 5, 223, 16, 65, 237, 132, 196, 241,
			39, 76, 133, 45, 252, 131, 88, 0,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("08c12007af16d1ee55fffe92cef808c77e318dae70c3bc70cb6361f49d517f1b68")
				.unwrap(),
		),
		RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				159, 156, 202, 179, 128, 169, 14, 227, 176, 79, 118, 180, 62, 164, 2, 234, 123, 30,
				77, 126, 232, 124, 42, 186, 239, 208, 21, 217, 228, 246, 148, 74, 100, 25, 247,
				251, 82, 100, 37, 16, 146, 122, 164, 5, 2, 165, 212, 192, 221, 167, 199, 8, 231,
				149, 158, 216, 194, 200, 62, 15, 53, 200, 188, 207, 0, 79, 211, 88, 194, 211, 54,
				1, 206, 53, 72, 118, 155, 184, 233, 166, 245, 224, 16, 254, 209, 235, 153, 85, 53,
				145, 33, 186, 218, 118, 144, 35, 189, 241, 63, 229, 52, 237, 231, 39, 176, 202, 93,
				247, 85, 131, 16, 193, 247, 180, 33, 138, 255, 102, 190, 213, 129, 174, 182, 167,
				3, 126, 184, 221, 99, 114, 238, 219, 157, 125, 230, 179, 160, 89, 202, 230, 16, 91,
				199, 57, 158, 225, 142, 125, 12, 211, 164, 78, 9, 4, 155, 106, 157, 41, 233, 188,
				237, 205, 184, 53, 0, 190, 24, 215, 42, 44, 184, 120, 58, 196, 198, 190, 114, 50,
				98, 240, 15, 213, 77, 163, 24, 3, 212, 125, 93, 175, 169, 249, 24, 27, 191, 113,
				89, 59, 169, 40, 87, 250, 144, 159, 118, 171, 232, 92, 217, 5, 179, 152, 249, 247,
				71, 239, 26, 180, 82, 177, 226, 132, 185, 3, 33, 162, 120, 98, 87, 109, 57, 100,
				202, 162, 57, 230, 44, 31, 63, 213, 30, 222, 241, 78, 162, 118, 120, 70, 196, 128,
				72, 223, 110, 5, 17, 151, 97, 214, 43, 57, 157, 1, 59, 87, 96, 17, 159, 174, 144,
				217, 159, 87, 36, 113, 41, 155, 186, 252, 162, 46, 22, 80, 133, 3, 113, 248, 11,
				118, 144, 155, 188, 77, 166, 40, 119, 107, 15, 233, 47, 47, 101, 77, 167, 141, 235,
				148, 34, 218, 164, 168, 71, 20, 239, 71, 24, 12, 109, 146, 232, 243, 65, 31, 72,
				186, 131, 190, 43, 227, 157, 41, 49, 126, 136, 51, 41, 50, 213, 37, 186, 223, 87,
				248, 34, 43, 132, 34, 0, 143, 75, 79, 43, 74, 183, 26, 2, 168, 53, 203, 208, 159,
				69, 107, 124, 33, 68, 113, 206, 127, 216, 158, 15, 52, 206, 1, 101, 109, 199, 13,
				131, 122, 29, 131, 133, 125, 219, 70, 69, 144, 133, 68, 233, 67, 203, 132, 160,
				143, 101, 84, 110, 15, 175, 111, 124, 24, 185, 222, 154, 238, 77, 241, 105, 8, 224,
				230, 43, 178, 49, 95, 137, 33, 227, 118, 207, 239, 56, 21, 51, 220, 22, 48, 162,
				22, 118, 229, 215, 248, 112, 198, 126, 180, 27, 161, 237, 56, 2, 220, 129, 126, 11,
				104, 8, 133, 190, 162, 204, 3, 63, 249, 173, 210, 152, 252, 143, 157, 79, 228, 232,
				230, 72, 164, 131, 183, 151, 230, 219, 186, 21, 34, 154, 219, 215, 231, 179, 47,
				217, 44, 115, 203, 157, 35, 195, 113, 235, 194, 102, 96, 205, 24, 221, 213, 147,
				120, 178, 221, 153, 146, 44, 172, 131, 77, 21, 61, 15, 5, 6, 205, 164, 203, 76,
				228, 29, 126, 136, 88, 230, 210, 62, 164, 103, 125, 55, 231, 129, 89, 61, 222, 50,
				71, 71, 75, 230, 70, 80, 85, 193, 136, 183, 222, 146, 46, 235, 0, 222, 118, 32, 70,
				85, 39, 92, 233, 211, 169, 159, 207, 145, 13, 206, 125, 3, 45, 51, 64, 167, 179,
				133, 83, 57, 190, 51, 239, 211, 74, 116, 75, 71, 248, 249, 184, 13, 31, 129, 107,
				104, 179, 76, 194, 186, 4, 13, 122, 167, 254, 126, 153, 50, 8, 1, 200, 203, 213,
				230, 217, 97, 105, 50, 208, 126, 180, 113, 81, 152, 238, 123, 157, 232, 19, 164,
				159, 164, 89, 75, 33, 70, 140, 204, 158, 236, 10, 226, 102, 14, 88, 134, 82, 131,
				36, 195, 127, 158, 81, 252, 223, 165, 11, 52, 105, 245, 245, 228, 235, 168, 175,
				52, 175, 76, 157, 120, 208, 99, 135, 210, 81, 114, 230, 181,
			],
		},
	);
	gen.with_reward(output, kernel)
}

/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2021, 1, 6).and_hms(18, 0, 0),
		prev_root: Hash::from_hex(
			"0000000000000000000a0516fb3ca4b824b4d0bac47c898fe017efb503dbfc90",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"510616ec823bd52628191c585f5bf1eb4b46250c5560198562ecedefbf512ffc",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"9a19e9adedfc97dc20a92ca9a6889cfd783c4613e99ff394e61761fe92ffc5b4",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"833064aa9cf462d6161b7f7ba4e36cd2fd569506268990a3888b962c7c7c692f",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(1),
			secondary_scaling: 1856,
			nonce: 41,
			proof: Proof {
				nonces: vec![
					16464203, 21796560, 26535589, 26809399, 45502065, 48615426, 84455592, 85871836,
					97499213, 102599374, 117017125, 129487590, 148919854, 158778147, 164449139,
					167160335, 171441196, 176277354, 185249494, 206566780, 211359115, 219703977,
					229855526, 278785541, 298893156, 301831808, 345844235, 347666201, 348357780,
					351406382, 355875296, 365697523, 372702881, 373845408, 405053514, 423731413,
					478048270, 481797665, 501317997, 506684390, 526698144, 533304543,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex("09364441178302c8d6624f4937b075cef103369b23c9bcf57851b3addc391efdcb")
				.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			39, 109, 13, 181, 102, 33, 35, 54, 80, 255, 98, 176, 130, 123, 97, 228, 219, 233, 106,
			97, 151, 126, 53, 130, 148, 176, 189, 1, 153, 153, 106, 103, 158, 185, 37, 85, 34, 249,
			210, 241, 16, 39, 93, 148, 249, 115, 53, 187, 9, 122, 8, 193, 59, 112, 32, 90, 130,
			151, 120, 103, 18, 166, 254, 166,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("09a9fe7abad04dfa5f8cd7772417be124f8f3f636511f5b7f0314c1b6d8b8ee6c6")
				.unwrap(),
		),
		RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				158, 81, 253, 205, 122, 218, 50, 57, 56, 162, 2, 91, 234, 45, 60, 253, 237, 9, 120,
				239, 110, 9, 191, 82, 61, 66, 36, 216, 116, 61, 188, 0, 244, 74, 197, 129, 38, 42,
				243, 44, 115, 245, 222, 234, 45, 253, 212, 17, 212, 184, 74, 119, 36, 25, 199, 127,
				205, 138, 170, 15, 88, 187, 94, 51, 14, 95, 26, 58, 16, 208, 96, 254, 217, 156, 16,
				100, 240, 166, 254, 97, 101, 1, 29, 129, 26, 66, 159, 242, 17, 101, 57, 20, 134,
				239, 92, 44, 31, 24, 72, 167, 229, 150, 57, 118, 125, 29, 82, 76, 9, 112, 176, 82,
				50, 86, 252, 9, 13, 101, 230, 94, 235, 25, 55, 12, 67, 27, 76, 241, 90, 216, 32,
				60, 164, 77, 198, 144, 46, 225, 85, 205, 163, 211, 118, 132, 152, 142, 4, 69, 49,
				233, 67, 70, 225, 81, 206, 101, 12, 16, 171, 73, 209, 212, 162, 210, 46, 152, 41,
				100, 96, 193, 117, 119, 185, 137, 249, 210, 217, 0, 0, 113, 180, 3, 166, 137, 11,
				93, 198, 220, 175, 184, 177, 113, 31, 152, 146, 205, 246, 131, 81, 122, 164, 158,
				70, 112, 243, 53, 159, 175, 79, 133, 240, 236, 6, 145, 61, 197, 12, 205, 174, 173,
				28, 13, 182, 95, 242, 194, 59, 94, 1, 136, 171, 30, 7, 89, 194, 29, 34, 96, 146, 5,
				28, 253, 217, 150, 1, 92, 51, 149, 186, 243, 15, 20, 158, 76, 153, 213, 49, 4, 248,
				58, 62, 26, 134, 228, 60, 43, 187, 251, 79, 139, 140, 7, 96, 214, 18, 107, 33, 17,
				91, 20, 183, 23, 112, 175, 14, 31, 241, 167, 120, 201, 82, 92, 224, 248, 217, 41,
				160, 177, 189, 71, 116, 59, 23, 172, 165, 69, 36, 48, 115, 7, 252, 15, 85, 55, 140,
				239, 232, 251, 202, 57, 57, 41, 67, 29, 78, 182, 6, 251, 194, 209, 73, 228, 78, 48,
				5, 59, 68, 75, 34, 92, 233, 66, 73, 236, 36, 128, 54, 168, 149, 70, 197, 131, 39,
				35, 3, 111, 202, 70, 203, 36, 205, 202, 142, 229, 20, 104, 119, 80, 193, 41, 183,
				5, 39, 246, 61, 239, 54, 182, 63, 47, 104, 210, 145, 136, 49, 135, 63, 85, 151, 33,
				219, 160, 207, 135, 42, 127, 133, 244, 151, 248, 209, 238, 6, 36, 34, 58, 76, 174,
				185, 130, 84, 25, 112, 120, 208, 174, 227, 47, 57, 176, 77, 255, 132, 224, 71, 245,
				37, 7, 227, 137, 247, 223, 161, 225, 76, 188, 100, 120, 34, 239, 67, 215, 146, 138,
				85, 213, 96, 204, 220, 217, 182, 95, 59, 87, 52, 69, 38, 50, 103, 254, 83, 59, 25,
				5, 143, 147, 114, 43, 144, 175, 198, 131, 142, 108, 48, 174, 227, 39, 232, 228,
				157, 216, 144, 97, 187, 42, 176, 143, 212, 190, 1, 101, 57, 9, 247, 61, 217, 204,
				28, 80, 15, 229, 73, 252, 237, 61, 20, 31, 216, 182, 246, 30, 217, 102, 242, 237,
				4, 52, 85, 1, 255, 38, 93, 153, 17, 25, 194, 133, 169, 24, 77, 41, 178, 213, 246,
				71, 85, 182, 179, 209, 53, 91, 10, 65, 197, 231, 181, 128, 39, 76, 147, 255, 197,
				55, 43, 31, 70, 131, 106, 187, 70, 145, 99, 110, 223, 59, 182, 35, 179, 227, 170,
				244, 193, 76, 235, 79, 235, 38, 97, 159, 147, 86, 234, 122, 219, 135, 37, 165, 121,
				240, 170, 12, 221, 217, 190, 198, 225, 246, 165, 244, 232, 13, 239, 68, 43, 82, 72,
				95, 234, 181, 8, 64, 25, 99, 156, 245, 196, 119, 162, 41, 93, 107, 57, 65, 3, 146,
				45, 130, 66, 85, 239, 175, 110, 24, 101, 61, 92, 76, 76, 62, 209, 102, 30, 219,
				166, 155, 55, 178, 13, 99, 15, 96, 201, 125, 184, 43, 214, 68, 204, 118, 20, 63,
				153, 129, 68, 137, 14, 90, 230, 190, 251, 199, 48, 57, 103,
			],
		},
	);
	gen.with_reward(output, kernel)
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
			"edc758c1370d43e1d733f70f58cf187c3be8242830429b1676b89fd91ccf2dab"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"022061f86c75ad5bd66fcd747be34517b661a967097a1807349f61aa03e64b20"
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
			"413577e7097c2db9dcaa8e4f872c38554420105cd3c949b6dedda88ea9ede157"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"c313e54bbd149e384e0adeb92c0d238d7d21e2ee3c43d6e49f85fb378ae0611a"
		);
	}
}
