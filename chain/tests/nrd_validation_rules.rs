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

use grin_chain as chain;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;

use self::chain_test_helper::{
	build_block, build_block_from_prev, clean_output_dir, genesis_block, init_chain,
};
use crate::chain::{Error, Options};
use crate::core::core::{KernelFeatures, NRDRelativeHeight, TxKernel};
use crate::core::libtx::{aggsig, build, ProofBuilder};
use crate::core::{consensus, global};
use crate::keychain::{BlindingFactor, ExtKeychain, Keychain};
use grin_core::address::Address;
use rand::thread_rng;

#[test]
fn process_block_nrd_validation() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".bmw.nrd_kernel";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());
	let mut pri_views = vec![];
	let mut outputs = vec![];

	for _ in 1..9 {
		let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		pri_views.push(pri_view);
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![],
			recipient_addr,
			private_nonce,
			true,
		);
		outputs.push(block.outputs()[0]);
		chain.process_block(block, Options::NONE)?;
	}

	let index0: u64 = chain.get_output_pos(&outputs[0].commitment()).unwrap() - 1;
	let index1: u64 = chain.get_output_pos(&outputs[1].commitment()).unwrap() - 1;

	assert_eq!(chain.head()?.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000.into(),
		relative_height: NRDRelativeHeight::new(2)?,
	});

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&keychain.secp());
	let skey = excess.secret_key(&keychain.secp()).unwrap();
	kernel.excess = keychain.secp().commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&keychain.secp()).unwrap();
	kernel.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey)).unwrap();
	kernel.verify().unwrap();

	let tx1 = build::transaction_with_kernel(
		&[
			build::input(consensus::REWARD1, pri_views[0].clone(), outputs[0], index0),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		&[
			build::input(consensus::REWARD1, pri_views[1].clone(), outputs[1], index1),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	// Block containing both tx1 and tx2 is invalid.
	// Not valid for two duplicate NRD kernels to co-exist in same block.
	// Jump through some hoops to build an invalid block by disabling the feature flag.
	// TODO - We need a good way of building invalid stuff in tests.
	let block_invalid_9 = {
		global::set_local_nrd_enabled(false);
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![tx1.clone(), tx2.clone()],
			recipient_addr,
			private_nonce,
			true,
		);
		global::set_local_nrd_enabled(true);
		block
	};
	assert!(chain.process_block(block_invalid_9, Options::NONE).is_err());

	assert_eq!(chain.head()?.height, 8);

	// Block containing tx1 is valid.
	let block_valid_9 = {
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![tx1.clone()],
			recipient_addr,
			private_nonce,
			true,
		);

		block
	};
	chain.process_block(block_valid_9, Options::NONE)?;

	// Block at height 10 is invalid if it contains tx2 due to NRD rule (relative_height=2).
	// Jump through some hoops to build an invalid block by disabling the feature flag.
	// TODO - We need a good way of building invalid stuff in tests.
	let block_invalid_10 = {
		global::set_local_nrd_enabled(false);
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![tx1.clone(), tx2.clone()],
			recipient_addr,
			private_nonce,
			false,
		);
		global::set_local_nrd_enabled(true);
		block
	};

	assert!(chain
		.process_block(block_invalid_10, Options::NONE)
		.is_err());

	// Block at height 10 is valid if we do not include tx2.
	let block_valid_10 = {
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![],
			recipient_addr,
			private_nonce,
			true,
		);

		block
	};

	chain.process_block(block_valid_10, Options::NONE)?;

	// Block at height 11 is valid with tx2 as NRD rule is met (relative_height=2).
	let block_valid_11 = {
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![tx2.clone()],
			recipient_addr,
			private_nonce,
			true,
		);

		block
	};
	chain.process_block(block_valid_11, Options::NONE)?;

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_nrd_validation_relative_height_1() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".bmw.nrd_kernel_relative_height_1";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());
	let mut pri_views = vec![];
	let mut outputs = vec![];

	for _ in 1..9 {
		let block = {
			let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			pri_views.push(pri_view);
			let recipient_addr =
				Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
			let (private_nonce, _pub_nonce) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let block = build_block(
				&chain,
				&keychain,
				vec![],
				recipient_addr,
				private_nonce,
				true,
			);
			outputs.push(block.outputs()[0]);

			block
		};
		chain.process_block(block, Options::NONE)?;
	}

	assert_eq!(chain.head()?.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000.into(),
		relative_height: NRDRelativeHeight::new(1)?,
	});

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&keychain.secp());
	let skey = excess.secret_key(&keychain.secp()).unwrap();
	kernel.excess = keychain.secp().commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&keychain.secp()).unwrap();
	kernel.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey)).unwrap();
	kernel.verify().unwrap();

	let index0: u64 = chain.get_output_pos(&outputs[0].commitment()).unwrap() - 1;
	let index1: u64 = chain.get_output_pos(&outputs[1].commitment()).unwrap() - 1;
	let tx1 = build::transaction_with_kernel(
		&[
			build::input(consensus::REWARD1, pri_views[0].clone(), outputs[0], index0),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		&[
			build::input(consensus::REWARD1, pri_views[1].clone(), outputs[1], index1),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	// Block containing both tx1 and tx2 is invalid.
	// Not valid for two duplicate NRD kernels to co-exist in same block.
	// Jump through some hoops here to build an "invalid" block.
	// TODO - We need a good way of building invalid stuff for tests.
	let block_invalid_9 = {
		global::set_local_nrd_enabled(false);
		let block = {
			let (_pri_view, pub_view) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let recipient_addr =
				Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
			let (private_nonce, _pub_nonce) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let block = build_block(
				&chain,
				&keychain,
				vec![tx1.clone(), tx2.clone()],
				recipient_addr,
				private_nonce,
				false,
			);

			block
		};
		global::set_local_nrd_enabled(true);
		block
	};

	assert!(chain.process_block(block_invalid_9, Options::NONE).is_err());

	assert_eq!(chain.head()?.height, 8);

	// Block containing tx1 is valid.
	let block_valid_9 = {
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![tx1.clone()],
			recipient_addr,
			private_nonce,
			true,
		);

		block
	};
	chain.process_block(block_valid_9, Options::NONE)?;

	// Block at height 10 is valid with tx2 as NRD rule is met (relative_height=1).
	let block_valid_10 = {
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let block = build_block(
			&chain,
			&keychain,
			vec![tx2.clone()],
			recipient_addr,
			private_nonce,
			true,
		);

		block
	};
	chain.process_block(block_valid_10, Options::NONE)?;

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_nrd_validation_fork() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".bmw.nrd_kernel_fork";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());
	let mut pri_views = vec![];
	let mut outputs = vec![];

	for _ in 1..9 {
		let block = {
			let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			pri_views.push(pri_view);
			let recipient_addr =
				Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
			let (private_nonce, _pub_nonce) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let block = build_block(
				&chain,
				&keychain,
				vec![],
				recipient_addr,
				private_nonce,
				true,
			);

			outputs.push(block.outputs()[0]);

			block
		};
		chain.process_block(block, Options::NONE)?;
	}

	let header_8 = chain.head_header()?;
	assert_eq!(header_8.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000.into(),
		relative_height: NRDRelativeHeight::new(2)?,
	});

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&keychain.secp());
	let skey = excess.secret_key(&keychain.secp()).unwrap();
	kernel.excess = keychain.secp().commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&keychain.secp()).unwrap();
	kernel.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey)).unwrap();
	kernel.verify().unwrap();

	let index0: u64 = chain.get_output_pos(&outputs[0].commitment()).unwrap() - 1;
	let index1: u64 = chain.get_output_pos(&outputs[1].commitment()).unwrap() - 1;

	let tx1 = build::transaction_with_kernel(
		&[
			build::input(consensus::REWARD1, pri_views[0].clone(), outputs[0], index0),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		&[
			build::input(consensus::REWARD1, pri_views[1].clone(), outputs[1], index1),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	// Block containing tx1 is valid.
	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	let (private_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let block_valid_9 = build_block_from_prev(
		&header_8,
		&chain,
		&keychain,
		vec![tx1.clone()],
		recipient_addr,
		private_nonce.clone(),
		true,
	);
	chain.process_block(block_valid_9.clone(), Options::NONE)?;

	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	// Block at height 10 is valid if we do not include tx2.
	let block_valid_10 = build_block_from_prev(
		&block_valid_9.header,
		&chain,
		&keychain,
		vec![],
		recipient_addr,
		private_nonce.clone(),
		true,
	);
	chain.process_block(block_valid_10, Options::NONE)?;

	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	// Process an alternative "fork" block also at height 9.
	// The "other" block at height 9 should not affect this one in terms of NRD kernels
	// as the recent kernel index should be rewound.
	let block_valid_9b = build_block_from_prev(
		&header_8,
		&chain,
		&keychain,
		vec![tx1.clone()],
		recipient_addr,
		private_nonce.clone(),
		true,
	);
	chain.process_block(block_valid_9b.clone(), Options::NONE)?;

	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	// Process an alternative block at height 10 on this same fork.
	let block_valid_10b = build_block_from_prev(
		&block_valid_9b.header,
		&chain,
		&keychain,
		vec![],
		recipient_addr,
		private_nonce.clone(),
		true,
	);
	chain.process_block(block_valid_10b.clone(), Options::NONE)?;

	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	// Block at height 11 is valid with tx2 as NRD rule is met (relative_height=2).
	let block_valid_11b = build_block_from_prev(
		&block_valid_10b.header,
		&chain,
		&keychain,
		vec![tx2.clone()],
		recipient_addr,
		private_nonce.clone(),
		true,
	);
	chain.process_block(block_valid_11b, Options::NONE)?;
	clean_output_dir(chain_dir);

	Ok(())
}
