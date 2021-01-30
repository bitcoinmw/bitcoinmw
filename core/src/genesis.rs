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
		timestamp: Utc.ymd(2021, 1, 6).and_hms(0, 0, 0),
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
			"00000000000000000002f0dd457b978032f9b778c06f13483eff602a69631ba0",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"7c7213b098af581a13d04e54874de7b30cce6b5878bb2a2ab538939029c22531",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"b04cfb34f3af0e1e76c92c206d929cdd5f841fc4b5af98bc14c08cb94fd3b914",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"363db8cf839f3270680f3a3912ff590fe7fe3629126786e9f7ea831465bff022",
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
					14206504, 50628124, 55865004, 77594321, 96431633, 112728589, 121956595,
					145455501, 173371452, 183882471, 189301818, 201528628, 212007840, 213181583,
					217677751, 229228772, 241453643, 247650850, 277077896, 304240308, 305640196,
					310972741, 314673341, 319079893, 326125089, 371999710, 407468766, 414251026,
					414790007, 431627183, 434687064, 445420412, 456027741, 456883368, 461802343,
					465135263, 486760344, 514413666, 516637781, 517570451, 524070289, 528781770,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});

	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex("0881c768ad35a109d42bb4e40d770eb2f8578d7cc77baa8455a0b4e08fe391ffde")
				.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			221, 219, 25, 99, 51, 3, 185, 86, 17, 35, 18, 163, 124, 46, 82, 235, 240, 42, 180, 66,
			87, 201, 27, 6, 128, 209, 52, 114, 249, 92, 251, 197, 174, 201, 169, 250, 81, 201, 106,
			115, 243, 227, 93, 25, 83, 135, 50, 95, 183, 135, 93, 208, 71, 254, 75, 40, 166, 201,
			9, 6, 86, 243, 239, 186,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("091afe4ecaa6bca0e986df43340daefa8a01ae91ba86094213399e508d28b4b057")
				.unwrap(),
		),
		RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				40, 115, 174, 29, 108, 20, 25, 97, 132, 184, 142, 61, 179, 168, 126, 175, 249, 7,
				188, 178, 80, 219, 204, 174, 188, 136, 177, 192, 246, 208, 4, 44, 164, 158, 62,
				225, 40, 161, 69, 192, 114, 192, 88, 48, 56, 157, 7, 35, 193, 103, 128, 62, 230,
				44, 181, 99, 107, 103, 191, 227, 151, 211, 13, 24, 6, 32, 181, 67, 170, 97, 7, 29,
				186, 167, 197, 99, 23, 244, 241, 85, 243, 232, 79, 112, 91, 209, 19, 52, 97, 215,
				77, 227, 121, 191, 123, 206, 16, 26, 211, 20, 109, 111, 214, 9, 29, 17, 102, 76,
				202, 212, 188, 194, 185, 223, 243, 229, 22, 14, 197, 37, 237, 175, 222, 195, 100,
				252, 135, 235, 46, 193, 205, 20, 202, 160, 44, 110, 44, 225, 149, 67, 90, 219, 129,
				100, 106, 74, 8, 231, 185, 82, 19, 175, 236, 59, 53, 239, 69, 129, 156, 59, 74, 99,
				210, 149, 30, 151, 15, 10, 120, 118, 49, 207, 83, 76, 230, 1, 202, 201, 146, 46,
				198, 68, 13, 136, 125, 140, 131, 52, 31, 232, 220, 203, 73, 90, 17, 74, 255, 255,
				36, 255, 179, 75, 227, 166, 94, 90, 158, 194, 169, 186, 43, 20, 55, 34, 11, 82,
				171, 120, 87, 88, 66, 249, 206, 28, 86, 221, 6, 74, 251, 111, 237, 30, 33, 126, 45,
				20, 211, 83, 102, 147, 171, 132, 163, 34, 119, 55, 43, 131, 4, 65, 22, 143, 69, 0,
				129, 215, 90, 131, 100, 209, 170, 183, 171, 94, 74, 252, 89, 99, 47, 152, 125, 128,
				32, 12, 220, 188, 137, 208, 21, 34, 67, 223, 17, 62, 245, 137, 78, 248, 159, 123,
				188, 157, 249, 211, 142, 220, 221, 18, 81, 134, 234, 177, 24, 54, 122, 165, 243,
				177, 185, 62, 220, 33, 25, 123, 232, 214, 135, 173, 41, 89, 130, 101, 196, 21, 40,
				228, 5, 170, 106, 57, 140, 221, 117, 224, 47, 10, 244, 55, 203, 82, 255, 55, 51,
				234, 155, 128, 171, 176, 229, 136, 215, 105, 143, 3, 1, 80, 148, 196, 7, 0, 182,
				85, 207, 22, 10, 2, 29, 39, 62, 130, 117, 129, 54, 227, 190, 221, 147, 152, 34, 2,
				54, 201, 85, 90, 119, 197, 111, 217, 230, 110, 43, 123, 195, 89, 188, 94, 216, 159,
				14, 152, 127, 184, 106, 88, 79, 83, 121, 1, 114, 133, 238, 57, 93, 83, 33, 226,
				156, 147, 109, 123, 44, 174, 33, 133, 117, 112, 239, 255, 186, 132, 210, 165, 117,
				43, 94, 222, 171, 203, 66, 79, 106, 120, 156, 65, 38, 154, 22, 226, 133, 155, 118,
				53, 150, 85, 234, 128, 170, 57, 232, 55, 64, 130, 209, 43, 201, 179, 253, 31, 235,
				21, 144, 86, 204, 149, 239, 111, 121, 44, 50, 175, 254, 134, 236, 218, 103, 150,
				182, 157, 97, 110, 228, 26, 138, 120, 99, 199, 169, 107, 16, 179, 254, 244, 215,
				124, 229, 104, 168, 177, 119, 169, 153, 12, 45, 19, 165, 39, 120, 173, 159, 103,
				48, 7, 155, 97, 77, 99, 229, 241, 171, 36, 168, 173, 171, 59, 92, 104, 131, 33,
				148, 149, 175, 196, 168, 119, 145, 198, 200, 171, 30, 11, 202, 218, 76, 53, 160,
				100, 228, 48, 71, 105, 107, 211, 137, 211, 126, 96, 252, 70, 210, 243, 78, 234,
				133, 135, 222, 131, 115, 127, 190, 7, 197, 74, 119, 35, 10, 48, 164, 204, 50, 70,
				227, 125, 11, 215, 85, 20, 236, 125, 253, 83, 142, 164, 115, 20, 200, 73, 85, 67,
				54, 93, 112, 156, 22, 234, 60, 58, 22, 181, 220, 250, 131, 219, 225, 205, 33, 213,
				220, 77, 50, 159, 215, 95, 32, 109, 67, 132, 95, 189, 158, 212, 120, 164, 62, 104,
				162, 184, 169, 4, 252, 24, 124, 159, 16, 114, 174, 166, 212, 215, 18, 154, 78, 137,
				137, 175, 45, 81, 91, 34, 187, 189, 254, 45, 116, 107, 219,
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
