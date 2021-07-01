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
use rand::thread_rng;

use self::chain_test_helper::{clean_output_dir, genesis_block, init_chain, new_block};
use crate::chain::{Chain, Options};
use crate::core::core::{Block, KernelFeatures, NRDRelativeHeight, Transaction};
use crate::core::libtx::{build, ProofBuilder};
use crate::core::{consensus, global, pow};
use crate::keychain::{ExtKeychain, Keychain};
use grin_core::address::Address;

use chrono::Duration;

#[derive(Debug)]
pub enum Error {
	Chain,
}

fn build_block<K>(
	chain: &Chain,
	keychain: &K,
	txs: Vec<Transaction>,
	recipient_address: Address,
) -> Block
where
	K: Keychain,
{
	let prev = chain.head_header().unwrap();
	let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());

	let mut block = new_block(
		&txs,
		keychain,
		&ProofBuilder::new(keychain),
		&prev,
		recipient_address,
	);

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(&mut block).unwrap();

	let edge_bits = global::min_edge_bits();
	block.header.pow.proof.edge_bits = edge_bits;
	pow::pow_size(
		&mut block.header,
		next_header_info.difficulty,
		global::proofsize(),
		edge_bits,
	)
	.unwrap();

	block
}

#[test]
fn mine_block_with_nrd_kernel_and_nrd_feature_enabled() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".bmw.nrd_kernel";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let pb = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());
	let mut recipient_addrs = vec![];
	let mut outputs = vec![];
	let mut pri_views = vec![];

	for _ in 1..9 {
		let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		println!(
			"gen recipient_addr/pri_view = {}, {:?}",
			recipient_addr, pri_view
		);
		recipient_addrs.push(recipient_addr.clone());

		let block = build_block(&chain, &keychain, vec![], recipient_addr);
		chain.process_block(block.clone(), Options::MINE).unwrap();
		let output = block.outputs()[0];
		println!("output = {:?}", output);
		outputs.push(output);
		pri_views.push(pri_view);
	}

	assert_eq!(chain.head().unwrap().height, 8);
	println!(
		"output = {:?}, recipient_addr = {}, pri_view = {:?}",
		outputs[0], recipient_addrs[0], pri_views[0]
	);
	let index: u64 = chain.get_output_pos(&outputs[0].commitment()).unwrap() - 1;
	let tx = build::transaction(
		KernelFeatures::NoRecentDuplicate {
			fee: 20000.into(),
			relative_height: NRDRelativeHeight::new(1440).unwrap(),
		},
		&[
			build::input(consensus::REWARD1, pri_views[0].clone(), outputs[0], index),
			build::output_rand(consensus::REWARD1 - 20000),
		],
		&keychain,
		&pb,
	)
	.unwrap();

	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let block = build_block(&chain, &keychain, vec![tx], recipient_addr);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();

	clean_output_dir(chain_dir);

	Ok(())
}
