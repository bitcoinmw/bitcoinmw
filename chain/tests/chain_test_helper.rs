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
use self::chain::types::Options;
use self::chain::Chain;
use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::Block;
use self::core::genesis;
use self::core::global::ChainTypes;
use self::core::libtx;
use self::core::{consensus, global, pow};
use self::keychain::Keychain;
use self::util::RwLock;
use chrono::Duration;
use grin_chain as chain;
use grin_core as core;
use grin_core::address::Address;
use grin_core::core::pmmr;
use grin_core::core::BlockHeader;
use grin_core::core::Transaction;
use grin_core::libtx::proof::PaymentId;
use grin_core::libtx::proof::ProofBuild;
use grin_core::libtx::ProofBuilder;
use grin_core::pow::Difficulty;
use grin_keychain as keychain;
use grin_keychain::keychain::SecretKey;
use grin_util as util;
use rand::thread_rng;
use std::fs;
use std::sync::Arc;

#[allow(dead_code)]
pub fn build_block_from_prev<K>(
	header: &BlockHeader,
	chain: &Chain,
	keychain: &K,
	txs: Vec<Transaction>,
	recipient_address: Address,
	private_nonce: SecretKey,
	set_roots: bool,
) -> Block
where
	K: Keychain,
{
	build_block_impl(
		header,
		chain,
		keychain,
		txs,
		recipient_address,
		private_nonce,
		set_roots,
	)
}

#[allow(dead_code)]
pub fn build_block<K>(
	chain: &Chain,
	keychain: &K,
	txs: Vec<Transaction>,
	recipient_address: Address,
	private_nonce: SecretKey,
	set_roots: bool,
) -> Block
where
	K: Keychain,
{
	build_block_impl(
		&chain.head_header().unwrap(),
		chain,
		keychain,
		txs,
		recipient_address,
		private_nonce,
		set_roots,
	)
}

fn build_block_impl<K>(
	prev: &BlockHeader,
	chain: &Chain,
	keychain: &K,
	txs: Vec<Transaction>,
	recipient_address: Address,
	private_nonce: SecretKey,
	set_roots: bool,
) -> Block
where
	K: Keychain,
{
	let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());

	let mut block = new_block_with_private_nonce(
		&txs,
		keychain,
		&ProofBuilder::new(keychain),
		&prev,
		recipient_address,
		private_nonce,
	);

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	if set_roots {
		chain.set_txhashset_roots(&mut block).unwrap();
	} else {
		chain.set_prev_root_only(&mut block.header).unwrap();
		block.header.output_mmr_size = pmmr::insertion_to_pmmr_index(prev.output_mmr_count() + 1);
		block.header.kernel_mmr_size = pmmr::insertion_to_pmmr_index(prev.kernel_mmr_count() + 1);
	}

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

#[allow(dead_code)]
pub fn new_block<K, B>(
	txs: &[Transaction],
	keychain: &K,
	builder: &B,
	previous_header: &BlockHeader,
	recipient_addr: Address,
) -> Block
where
	K: Keychain,
	B: ProofBuild,
{
	let (private_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	new_block_with_private_nonce(
		txs,
		keychain,
		builder,
		previous_header,
		recipient_addr,
		private_nonce,
	)
}

#[allow(dead_code)]
pub fn new_block_with_private_nonce<K, B>(
	txs: &[Transaction],
	keychain: &K,
	builder: &B,
	previous_header: &BlockHeader,
	recipient_addr: Address,
	private_nonce: SecretKey,
) -> Block
where
	K: Keychain,
	B: ProofBuild,
{
	let fees = txs
		.iter()
		.map(|tx| tx.fee(previous_header.height + 1))
		.sum();

	let payment_id = PaymentId::new();

	let reward_output = libtx::reward::nit_output(
		keychain,
		builder,
		private_nonce,
		recipient_addr.clone(),
		payment_id,
		fees,
		false,
		1,
	)
	.unwrap();

	Block::new(
		&previous_header,
		txs,
		Difficulty::min_dma(),
		reward_output,
		None,
	)
	.unwrap()
}

#[allow(dead_code)]
pub fn clean_output_dir(dir_name: &str) {
	let _ = fs::remove_dir_all(dir_name);
}

pub fn init_chain(dir_name: &str, genesis: Block) -> Chain {
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
	Chain::init(
		dir_name.to_string(),
		Arc::new(NoopAdapter {}),
		genesis,
		pow::verify_size,
		verifier_cache,
		false,
		None,
	)
	.unwrap()
}

/// Build genesis block with reward (non-empty, like we have in mainnet).
pub fn genesis_block<K>(_keychain: &K) -> Block
where
	K: Keychain,
{
	genesis::genesis_dev().without_reward()
}

/// Mine a chain of specified length to assist with automated tests.
/// Probably a good idea to call clean_output_dir at the beginning and end of each test.
#[allow(dead_code)]
pub fn mine_chain(dir_name: &str, chain_length: u64) -> Chain {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let genesis = genesis_block(&keychain);
	let mut chain = init_chain(dir_name, genesis.clone());
	mine_some_on_top(&mut chain, chain_length, &keychain);
	chain
}

#[allow(dead_code)]
fn mine_some_on_top<K>(chain: &mut Chain, chain_length: u64, keychain: &K)
where
	K: Keychain,
{
	for n in 1..chain_length {
		let prev = chain.head_header().unwrap();
		let next_header_info =
			consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let reward = libtx::reward::nit_output(
			keychain,
			&libtx::ProofBuilder::new(keychain),
			private_nonce,
			recipient_addr.clone(),
			PaymentId::new(),
			0,
			false,
			prev.height + 1,
		)
		.unwrap();
		let mut b =
			core::core::Block::new(&prev, &[], next_header_info.difficulty, reward, None).unwrap();
		b.header.timestamp = prev.timestamp + Duration::seconds(60);
		b.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(&mut b).unwrap();

		let edge_bits = global::min_edge_bits();
		b.header.pow.proof.edge_bits = edge_bits;
		pow::pow_size(
			&mut b.header,
			next_header_info.difficulty,
			global::proofsize(),
			edge_bits,
		)
		.unwrap();

		let bhash = b.hash();
		chain.process_block(b, Options::MINE).unwrap();

		// checking our new head
		let head = chain.head().unwrap();
		assert_eq!(head.height, n);
		assert_eq!(head.last_block_h, bhash);

		// now check the block_header of the head
		let header = chain.head_header().unwrap();
		assert_eq!(header.height, n);
		assert_eq!(header.hash(), bhash);

		// now check the block itself
		let block = chain.get_block(&header.hash()).unwrap();
		assert_eq!(block.header.height, n);
		assert_eq!(block.hash(), bhash);
		assert_eq!(block.outputs().len(), 1);

		// now check the block height index
		let header_by_height = chain.get_header_by_height(n).unwrap();
		assert_eq!(header_by_height.hash(), bhash);

		chain.validate(false).unwrap();
	}
}
