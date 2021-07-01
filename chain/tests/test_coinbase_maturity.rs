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

mod chain_test_helper;

use self::chain::types::NoopAdapter;
use self::chain::ErrorKind;
use self::chain_test_helper::new_block;
use self::core::address::Address;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::KernelFeatures;
use self::core::global::{self, ChainTypes};
use self::core::libtx::{build, ProofBuilder};
use self::core::{consensus, pow};
use self::util::RwLock;
use chrono::Duration;
use grin_chain as chain;
use grin_core as core;
use grin_keychain::{ExtKeychain, Keychain};
use grin_util as util;
use rand::thread_rng;
use std::fs;
use std::sync::Arc;

fn clean_output_dir(dir_name: &str) {
	let _ = fs::remove_dir_all(dir_name);
}

#[test]
fn test_coinbase_maturity() {
	util::init_test_logger();
	let chain_dir = ".bmw_coinbase";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let genesis_block = pow::mine_genesis_block().unwrap();

	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	{
		let chain = chain::Chain::init(
			chain_dir.to_string(),
			Arc::new(NoopAdapter {}),
			genesis_block,
			pow::verify_size,
			verifier_cache,
			false,
			None,
		)
		.unwrap();

		let prev = chain.head_header().unwrap();

		let next_header_info =
			consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
		let mut block = new_block(
			&[],
			&keychain,
			&ProofBuilder::new(&keychain),
			&prev,
			recipient_addr.clone(),
		);
		block.header.timestamp = prev.timestamp + Duration::seconds(60);
		block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(&mut block).unwrap();

		pow::pow_size(
			&mut block.header,
			next_header_info.difficulty,
			global::proofsize(),
			global::min_edge_bits(),
		)
		.unwrap();

		assert_eq!(block.outputs().len(), 1);
		let coinbase_output = block.outputs()[0];
		assert!(coinbase_output.is_coinbase());

		chain
			.process_block(block.clone(), chain::Options::MINE)
			.unwrap();

		let prev = chain.head_header().unwrap();

		let amount = consensus::REWARD1;

		let lock_height = 1 + global::coinbase_maturity();
		assert_eq!(lock_height, 4);

		// here we build a tx that attempts to spend the earlier coinbase output
		// this is not a valid tx as the coinbase output cannot be spent yet
		let index: u64 = chain.get_output_pos(&coinbase_output.commitment()).unwrap() - 1;
		let coinbase_txn = build::transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[
				build::input(amount, pri_view.clone(), coinbase_output, index),
				build::output_rand(amount - 2),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		let txs = &[coinbase_txn.clone()];
		let next_header_info =
			consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
		let mut block = new_block(
			txs,
			&keychain,
			&ProofBuilder::new(&keychain),
			&prev,
			recipient_addr.clone(),
		);
		block.header.timestamp = prev.timestamp + Duration::seconds(60);
		block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(&mut block).unwrap();

		// Confirm the tx attempting to spend the coinbase output
		// is not valid at the current block height given the current chain state.
		match chain.verify_coinbase_maturity(&coinbase_txn.inputs()) {
			Ok(_) => {}
			Err(e) => match e.kind() {
				ErrorKind::ImmatureCoinbase => {}
				_ => panic!("Expected transaction error with immature coinbase."),
			},
		}

		pow::pow_size(
			&mut block.header,
			next_header_info.difficulty,
			global::proofsize(),
			global::min_edge_bits(),
		)
		.unwrap();

		// mine enough blocks to increase the height sufficiently for
		// coinbase to reach maturity and be spendable in the next block
		for _ in 0..3 {
			let prev = chain.head_header().unwrap();

			let keychain = ExtKeychain::from_random_seed(false).unwrap();
			let builder = ProofBuilder::new(&keychain);

			let next_header_info =
				consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
			let mut block = new_block(
				&[],
				&keychain,
				&ProofBuilder::new(&keychain),
				&prev,
				recipient_addr.clone(),
			);

			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&mut block).unwrap();

			pow::pow_size(
				&mut block.header,
				next_header_info.difficulty,
				global::proofsize(),
				global::min_edge_bits(),
			)
			.unwrap();

			assert_eq!(block.outputs().len(), 1);
			let coinbase_output = block.outputs()[0];
			assert!(coinbase_output.is_coinbase());

			chain
				.process_block(block.clone(), chain::Options::MINE)
				.unwrap();

			let prev = chain.head_header().unwrap();

			let amount = consensus::REWARD1;

			let lock_height = 1 + global::coinbase_maturity();
			assert_eq!(lock_height, 4);

			// here we build a tx that attempts to spend the earlier coinbase output
			// this is not a valid tx as the coinbase output cannot be spent yet
			let index: u64 = chain.get_output_pos(&coinbase_output.commitment()).unwrap() - 1;
			let coinbase_txn = build::transaction(
				KernelFeatures::Plain { fee: 2.into() },
				&[
					build::input(amount, pri_view.clone(), coinbase_output, index),
					build::output_rand(amount - 2),
				],
				&keychain,
				&builder,
			)
			.unwrap();

			let txs = &[coinbase_txn.clone()];
			let next_header_info =
				consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
			let mut block = new_block(
				txs,
				&keychain,
				&ProofBuilder::new(&keychain),
				&prev,
				recipient_addr.clone(),
			);
			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&mut block).unwrap();

			// Confirm the tx attempting to spend the coinbase output
			// is not valid at the current block height given the current chain state.
			match chain.verify_coinbase_maturity(&coinbase_txn.inputs()) {
				Ok(_) => {}
				Err(e) => match e.kind() {
					ErrorKind::ImmatureCoinbase => {}
					_ => panic!("Expected transaction error with immature coinbase."),
				},
			}

			pow::pow_size(
				&mut block.header,
				next_header_info.difficulty,
				global::proofsize(),
				global::min_edge_bits(),
			)
			.unwrap();

			// mine enough blocks to increase the height sufficiently for
			// coinbase to reach maturity and be spendable in the next block
			for _ in 0..3 {
				let prev = chain.head_header().unwrap();

				let keychain = ExtKeychain::from_random_seed(false).unwrap();

				let next_header_info =
					consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
				let mut block = new_block(
					&[],
					&keychain,
					&ProofBuilder::new(&keychain),
					&prev,
					recipient_addr.clone(),
				);
				block.header.timestamp = prev.timestamp + Duration::seconds(60);
				block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

				chain.set_txhashset_roots(&mut block).unwrap();

				pow::pow_size(
					&mut block.header,
					next_header_info.difficulty,
					global::proofsize(),
					global::min_edge_bits(),
				)
				.unwrap();

				chain.process_block(block, chain::Options::MINE).unwrap();
			}

			let prev = chain.head_header().unwrap();

			// Confirm the tx spending the coinbase output is now valid.
			// The coinbase output has matured sufficiently based on current chain state.
			chain
				.verify_coinbase_maturity(&coinbase_txn.inputs())
				.unwrap();

			let txs = &[coinbase_txn];
			let next_header_info =
				consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
			let mut block = new_block(
				txs,
				&keychain,
				&ProofBuilder::new(&keychain),
				&prev,
				recipient_addr.clone(),
			);

			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&mut block).unwrap();

			pow::pow_size(
				&mut block.header,
				next_header_info.difficulty,
				global::proofsize(),
				global::min_edge_bits(),
			)
			.unwrap();

			let result = chain.process_block(block, chain::Options::MINE);
			match result {
				Ok(_) => (),
				Err(_) => panic!("we did not expect an error here"),
			};
		}
	}
	// Cleanup chain directory
	clean_output_dir(chain_dir);
}
