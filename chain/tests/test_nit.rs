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

use self::chain::types::NoopAdapter;
use self::core::address::Address;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::KernelFeatures;
use self::core::core::Transaction;
use self::core::core::Weighting;
use self::core::global::{self, ChainTypes};
use self::core::libtx::proof::PaymentId;
use self::core::libtx::{self, build, ProofBuilder};
use self::core::{consensus, pow};
use self::keychain::{ExtKeychain, Keychain};
use self::util::RwLock;
use chrono::Duration;
use grin_chain as chain;
use grin_core as core;
use grin_core::core::hash::Hashed;
use grin_core::core::CommitWrapper;
use grin_core::core::Inputs;
use grin_core::core::Output;
use grin_keychain as keychain;
use grin_util as util;
use rand::thread_rng;
use std::fs;
use std::sync::Arc;

#[derive(Debug)]
pub enum Error {
	Chain,
	Transaction,
}

fn clean_output_dir(dir_name: &str) {
	let _ = fs::remove_dir_all(dir_name);
}

#[test]
fn test_nit() -> Result<(), Error> {
	util::init_test_logger();
	let chain_dir = ".bmw_coinbase";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let genesis_block = pow::mine_genesis_block().unwrap();

	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	{
		let chain = chain::Chain::init(
			chain_dir.to_string(),
			Arc::new(NoopAdapter {}),
			genesis_block,
			pow::verify_size,
			verifier_cache.clone(),
			false,
			None,
		)
		.unwrap();

		let prev = chain.head_header().unwrap();

		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);

		let next_header_info =
			consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());

		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let payment_id = PaymentId::new();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let reward = libtx::reward::nit_output(
			&keychain,
			&builder,
			private_nonce,
			recipient_addr.clone(),
			payment_id,
			0,
			false,
			1,
		)
		.unwrap();
		let spending_output = reward.0;

		let mut block =
			core::core::Block::new(&prev, &[], next_header_info.difficulty, reward, None).unwrap();
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

		chain.validate(false).unwrap();
		let mut prev;

		let amount = consensus::REWARD1;

		let lock_height = 1 + global::coinbase_maturity();
		assert_eq!(lock_height, 4);

		// mine enough blocks to increase the height sufficiently for
		// coinbase to reach maturity and be spendable in the next block
		for _ in 0..3 {
			prev = chain.head_header().unwrap();

			let keychain = ExtKeychain::from_random_seed(false).unwrap();
			let builder = ProofBuilder::new(&keychain);

			let next_header_info =
				consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());

			let (private_nonce2, _pub_nonce2) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let (_pri_view2, pub_view2) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let payment_id2 = PaymentId::new();
			let recipient_addr2 =
				Address::from_one_pubkey(&pub_view2, global::ChainTypes::AutomatedTesting);
			let reward2 = libtx::reward::nit_output(
				&keychain,
				&builder,
				private_nonce2,
				recipient_addr2,
				payment_id2,
				0,
				false,
				1,
			)
			.unwrap();

			let mut block =
				core::core::Block::new(&prev, &[], next_header_info.difficulty, reward2, None)
					.unwrap();

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

			chain.validate(false).unwrap();
		}
		prev = chain.head_header().unwrap();

		// spend the nit output in the first block

		// here we build a tx that attempts to spend the earlier coinbase output
		let simulated_index: u64 = chain.get_output_pos(&spending_output.commitment()).unwrap();
		let simulated_rp_hash = (simulated_index - 1, spending_output.proof).hash();

		let (pri_view3, pub_view3) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let payment_id3 = PaymentId::new();
		let recipient_addr3 =
			Address::from_one_pubkey(&pub_view3, global::ChainTypes::AutomatedTesting);

		let coinbase_txn = build::transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[
				build::input_with_sig(
					amount,
					pri_view.clone(),
					pri_view,
					spending_output.identifier(),
					recipient_addr.clone(),
					simulated_rp_hash,
				),
				build::output_wrnp(
					amount - 2,
					pri_view3.clone(),
					recipient_addr3.clone(),
					payment_id3,
				),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		coinbase_txn.validate(
			Weighting::AsTransaction,
			verifier_cache.clone(),
			0,
			None,
			None,
		)?;
		chain.validate_tx(&coinbase_txn)?;

		let txs = &[coinbase_txn.clone()];
		let fees = txs.iter().map(|tx| tx.fee(prev.height + 1)).sum();

		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let payment_id = PaymentId::new();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let reward = libtx::reward::nit_output(
			&keychain,
			&builder,
			private_nonce,
			recipient_addr.clone(),
			payment_id,
			fees,
			false,
			1,
		)
		.unwrap();

		let next_header_info =
			consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
		let mut block =
			core::core::Block::new(&prev, txs, next_header_info.difficulty, reward, None).unwrap();
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

		assert_eq!(block.outputs().len(), 2);

		assert!(block.outputs()[0].is_coinbase() || block.outputs()[1].is_coinbase());
		assert!(!block.outputs()[0].is_coinbase() || !block.outputs()[1].is_coinbase());
		chain
			.process_block(block.clone(), chain::Options::MINE)
			.unwrap();

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

		chain.validate(false).unwrap();

		assert_eq!(chain.head_header()?.height, 5);

		// try a transaction with the previous r_sig
		let mut spending_output = coinbase_txn.outputs()[0];
		if spending_output.is_coinbase() {
			spending_output = coinbase_txn.outputs()[1];
		}
		let simulated_index: u64 = chain.get_output_pos(&spending_output.commitment()).unwrap();
		let simulated_rp_hash = (simulated_index - 1, spending_output.proof).hash();
		let tx = build::transaction(
			KernelFeatures::Plain { fee: 3.into() },
			&[
				build::input_with_sig(
					amount - 2,
					pri_view3.clone(),
					pri_view3.clone(),
					spending_output.identifier(),
					recipient_addr3.clone(),
					simulated_rp_hash,
				),
				build::output_wrnp(
					amount - 5,
					pri_view3.clone(),
					recipient_addr3.clone(),
					payment_id3,
				),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		let body = tx.body.clone();
		let output = body.outputs()[0];
		let original_r_sig = output.identifier.r_sig;

		// modify the r_sig with the previous coinbase txn (also tests verifier cache).
		let new_output = Output::new(
			output.identifier.features,
			output.identifier.commit,
			output.proof,
			coinbase_txn.body.outputs()[0].identifier.r_sig,
			output.identifier.view_tag,
			output.identifier.nonce,
			output.identifier.onetime_pubkey,
		);

		let tx = Transaction {
			body: tx.body.replace_outputs(vec![new_output].as_slice()),
			..tx
		};

		assert_eq!(
			tx.validate(
				Weighting::AsTransaction,
				verifier_cache.clone(),
				0,
				None,
				None
			)
			.is_ok(),
			false,
		);

		// modify the input sig
		let bad_input_sig = coinbase_txn.inputs().0[0].sig;
		let new_output = Output::new(
			output.identifier.features,
			output.identifier.commit,
			output.proof,
			original_r_sig,
			output.identifier.view_tag,
			output.identifier.nonce,
			output.identifier.onetime_pubkey,
		);

		let input = body.inputs();

		let new_input = {
			let cw = CommitWrapper {
				commit: input.0[0].commit,
				sig: bad_input_sig,
			};
			Inputs(vec![cw])
		};

		let tx2 = tx.clone();
		let tx2 = Transaction {
			body: tx2
				.body
				.replace_outputs(vec![new_output].as_slice())
				.replace_inputs(new_input),
			..tx2
		};

		// txn is valid because input_signatures are only validated on the block level
		// also need to make sure they are validated by the transaction pool as well
		assert_eq!(
			tx2.validate(Weighting::AsTransaction, verifier_cache, 0, None, None),
			Ok(()),
		);

		// try in a block
		prev = chain.head_header().unwrap();
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let payment_id = PaymentId::new();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let reward = libtx::reward::nit_output(
			&keychain,
			&builder,
			private_nonce,
			recipient_addr.clone(),
			payment_id,
			fees,
			false,
			1,
		)
		.unwrap();

		let next_header_info =
			consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
		let txs = &[tx.clone()];
		let mut block = core::core::Block::new(
			&prev,
			txs,
			next_header_info.difficulty,
			reward.clone(),
			None,
		)
		.unwrap();

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

		assert_eq!(
			chain
				.process_block(block.clone(), chain::Options::MINE)
				.is_ok(),
			false,
		);

		// now try tx2
		let txs = &[tx2.clone()];
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let fees = txs.iter().map(|tx| tx.fee(prev.height + 1)).sum();
		let reward = libtx::reward::nit_output(
			&keychain,
			&builder,
			private_nonce,
			recipient_addr.clone(),
			payment_id,
			fees,
			false,
			1,
		)
		.unwrap();
		let mut block =
			core::core::Block::new(&prev, txs, next_header_info.difficulty, reward, None).unwrap();
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

		// it will be false because block validation checks for input_sigs
		assert_eq!(
			format!(
				"{:?}",
				chain.process_block(block.clone(), chain::Options::MINE)
			)
			.contains("IncorrectSignature"),
			true,
		);
	}

	// Cleanup chain directory
	clean_output_dir(chain_dir);

	Ok(())
}

impl From<grin_chain::Error> for Error {
	fn from(_: grin_chain::Error) -> Error {
		Error::Chain
	}
}

impl From<grin_core::core::transaction::Error> for Error {
	fn from(_: grin_core::core::transaction::Error) -> Error {
		Error::Transaction
	}
}
