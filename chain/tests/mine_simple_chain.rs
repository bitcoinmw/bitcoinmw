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

use self::chain::types::{NoopAdapter, Tip};
use self::chain::Chain;
use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::{Block, BlockHeader, KernelFeatures, Transaction};
use self::core::global::ChainTypes;
use self::core::libtx::{self, build, ProofBuilder};
use self::core::pow::Difficulty;
use self::core::{consensus, global, pow};
use self::keychain::{ExtKeychain, Keychain};
use self::util::RwLock;
use crate::core::address::Address;
use crate::keychain::keychain::PublicKey;
use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use bmw_utxo::utxo_data::{ChainType, UtxoData};
use chrono::Duration;
use grin_chain as chain;
use grin_chain::{BlockStatus, ChainAdapter, Options};
use grin_core as core;
use grin_core::core::transaction::Error;
use grin_core::core::verifier_cache::VerifierCache;
use grin_core::core::Inputs;
use grin_core::core::TransactionBody;
use grin_core::core::Weighting;
use grin_core::libtx::proof::PaymentId;
use grin_core::libtx::reward;
use grin_keychain as keychain;
use grin_keychain::keychain::SecretKey;
use grin_keychain::BlindingFactor;
use grin_util as util;
use rand::thread_rng;
use std::sync::Arc;
use std::sync::Weak;

mod chain_test_helper;

use self::chain_test_helper::{build_block, clean_output_dir, init_chain, mine_chain, new_block};

/// Adapter to retrieve last status
pub struct StatusAdapter {
	pub last_status: RwLock<Option<BlockStatus>>,
}

impl StatusAdapter {
	pub fn new(last_status: RwLock<Option<BlockStatus>>) -> Self {
		StatusAdapter { last_status }
	}
}

impl ChainAdapter for StatusAdapter {
	fn block_accepted(&self, _b: &Block, status: BlockStatus, _opts: Options) {
		*self.last_status.write() = Some(status);
	}
}

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

/// Creates a `Chain` instance with `StatusAdapter` attached to it.
fn setup_with_status_adapter(
	dir_name: &str,
	genesis: Block,
	adapter: Arc<StatusAdapter>,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
) -> Chain {
	util::init_test_logger();
	clean_output_dir(dir_name);
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
	let chain = chain::Chain::init(
		dir_name.to_string(),
		adapter,
		genesis,
		pow::verify_size,
		verifier_cache,
		false,
		utxo_data,
	)
	.unwrap();

	chain
}

#[test]
fn mine_empty_chain() {
	let chain_dir = ".bmw.empty";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 1);
	assert_eq!(chain.head().unwrap().height, 0);
	clean_output_dir(chain_dir);
}

#[test]
fn mine_short_chain() {
	let chain_dir = ".bmw.short";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	assert_eq!(chain.head().unwrap().height, 3);
	clean_output_dir(chain_dir);
}

// Convenience wrapper for processing a full block on the test chain.
fn process_header(chain: &Chain, header: &BlockHeader) {
	chain
		.process_block_header(header, chain::Options::SKIP_POW)
		.unwrap();
}

// Convenience wrapper for processing a block header on the test chain.
fn process_block(chain: &Chain, block: &Block) {
	chain
		.process_block(block.clone(), chain::Options::SKIP_POW)
		.unwrap();
}

//
// a - b - c
//  \
//   - b'
//
// Process in the following order -
// 1. block_a
// 2. block_b
// 3. block_b'
// 4. header_c
// 5. block_c
//
#[test]
fn test_block_a_block_b_block_b_fork_header_c_fork_block_c() {
	let chain_dir = ".bmw.block_a_block_b_block_b_fork_header_c_fork_block_c";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();
	let genesis = pow::mine_genesis_block().unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(chain_dir, genesis.clone(), adapter.clone(), None);

	let block_a = prepare_block(&kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&chain, &block_a);

	let block_b = prepare_block(&kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&kc, &block_a.header, &chain, 2);

	process_block(&chain, &block_b);
	process_block(&chain, &block_b_fork);

	let block_c = prepare_block(&kc, &block_b.header, &chain, 3);
	process_header(&chain, &block_c.header);

	assert_eq!(chain.head().unwrap(), Tip::from_header(&block_b.header));
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_c.header)
	);

	process_block(&chain, &block_c);

	assert_eq!(chain.head().unwrap(), Tip::from_header(&block_c.header));
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_c.header)
	);

	clean_output_dir(chain_dir);
}

//
// a - b
//  \
//   - b' - c'
//
// Process in the following order -
// 1. block_a
// 2. block_b
// 3. block_b'
// 4. header_c'
// 5. block_c'
//
#[test]
fn test_block_a_block_b_block_b_fork_header_c_fork_block_c_fork() {
	let chain_dir = ".bmw.block_a_block_b_block_b_fork_header_c_fork_block_c_fork";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();
	let genesis = pow::mine_genesis_block().unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(chain_dir, genesis.clone(), adapter.clone(), None);

	let block_a = prepare_block(&kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&chain, &block_a);

	let block_b = prepare_block(&kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&kc, &block_a.header, &chain, 2);

	process_block(&chain, &block_b);
	process_block(&chain, &block_b_fork);

	let block_c_fork = prepare_block(&kc, &block_b_fork.header, &chain, 3);
	process_header(&chain, &block_c_fork.header);

	assert_eq!(chain.head().unwrap(), Tip::from_header(&block_b.header));
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_c_fork.header)
	);

	process_block(&chain, &block_c_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::from_header(&block_c_fork.header)
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_c_fork.header)
	);

	clean_output_dir(chain_dir);
}

//
// a - b - c
//  \
//   - b'
//
// Process in the following order -
// 1. block_a
// 2. header_b
// 3. header_b_fork
// 4. block_b_fork
// 5. block_b
// 6. block_c
//
#[test]
fn test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c() {
	let chain_dir = ".bmw.test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();
	let genesis = pow::mine_genesis_block().unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(chain_dir, genesis.clone(), adapter.clone(), None);

	let block_a = prepare_block(&kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&chain, &block_a);

	let block_b = prepare_block(&kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&kc, &block_a.header, &chain, 2);

	process_header(&chain, &block_b.header);
	process_header(&chain, &block_b_fork.header);
	process_block(&chain, &block_b_fork);
	process_block(&chain, &block_b);

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_b.header)
	);
	assert_eq!(
		chain.head().unwrap(),
		Tip::from_header(&block_b_fork.header)
	);

	let block_c = prepare_block(&kc, &block_b.header, &chain, 3);
	process_block(&chain, &block_c);

	assert_eq!(chain.head().unwrap(), Tip::from_header(&block_c.header));
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_c.header)
	);

	clean_output_dir(chain_dir);
}

//
// a - b
//  \
//   - b' - c'
//
// Process in the following order -
// 1. block_a
// 2. header_b
// 3. header_b_fork
// 4. block_b_fork
// 5. block_b
// 6. block_c_fork
//
#[test]
fn test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c_fork() {
	let chain_dir = ".bmw.test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c_fork";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();
	let genesis = pow::mine_genesis_block().unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(chain_dir, genesis.clone(), adapter.clone(), None);

	let block_a = prepare_block(&kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&chain, &block_a);

	let block_b = prepare_block(&kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&kc, &block_a.header, &chain, 2);

	process_header(&chain, &block_b.header);
	process_header(&chain, &block_b_fork.header);
	process_block(&chain, &block_b_fork);
	process_block(&chain, &block_b);

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_b.header)
	);
	assert_eq!(
		chain.head().unwrap(),
		Tip::from_header(&block_b_fork.header)
	);

	let block_c_fork = prepare_block(&kc, &block_b_fork.header, &chain, 3);
	process_block(&chain, &block_c_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::from_header(&block_c_fork.header)
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::from_header(&block_c_fork.header)
	);

	clean_output_dir(chain_dir);
}

#[test]
// This test creates a reorg at REORG_DEPTH by mining a block with difficulty that
// exceeds original chain total difficulty.
//
// Illustration of reorg with NUM_BLOCKS_MAIN = 6 and REORG_DEPTH = 5:
//
// difficulty:    1        2        3        4        5        6
//
//                       / [ 2  ] - [ 3  ] - [ 4  ] - [ 5  ] - [ 6  ] <- original chain
// [ Genesis ] -[ 1 ]- *
//                     ^ \ [ 2' ] - ................................  <- reorg chain with depth 5
//                     |
// difficulty:    1    |   24
//                     |
//                     \----< Fork point and chain reorg
fn mine_reorg() {
	// Test configuration
	const NUM_BLOCKS_MAIN: u64 = 6; // Number of blocks to mine in main chain
	const REORG_DEPTH: u64 = 5; // Number of blocks to be discarded from main chain after reorg

	const DIR_NAME: &str = ".bmw_reorg";
	clean_output_dir(DIR_NAME);

	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();

	let genesis = pow::mine_genesis_block().unwrap();
	{
		// Create chain that reports last block status
		let last_status = RwLock::new(None);
		let adapter = Arc::new(StatusAdapter::new(last_status));
		let chain = setup_with_status_adapter(DIR_NAME, genesis.clone(), adapter.clone(), None);

		// Add blocks to main chain with gradually increasing difficulty
		let mut prev = chain.head_header().unwrap();
		for n in 1..=NUM_BLOCKS_MAIN {
			let b = prepare_block(&kc, &prev, &chain, n);
			prev = b.header.clone();
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN);
		assert_eq!(head.hash(), prev.hash());

		// Reorg chain should exceed main chain's total difficulty to be considered
		let reorg_difficulty = head.total_difficulty.to_num();

		// Create one block for reorg chain forking off NUM_BLOCKS_MAIN - REORG_DEPTH height
		let fork_head = chain
			.get_header_by_height(NUM_BLOCKS_MAIN - REORG_DEPTH)
			.unwrap();
		let b = prepare_block(&kc, &fork_head, &chain, reorg_difficulty);
		let reorg_head = b.header.clone();
		chain.process_block(b, chain::Options::SKIP_POW).unwrap();

		// Check that reorg is correctly reported in block status
		let fork_point = chain.get_header_by_height(1).unwrap();
		assert_eq!(
			*adapter.last_status.read(),
			Some(BlockStatus::Reorg {
				prev: Tip::from_header(&fork_head),
				prev_head: head,
				fork_point: Tip::from_header(&fork_point)
			})
		);

		// Chain should be switched to the reorganized chain
		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN - REORG_DEPTH + 1);
		assert_eq!(head.hash(), reorg_head.hash());
	}

	// Cleanup chain directory
	clean_output_dir(DIR_NAME);
}

#[test]
fn mine_forks() {
	clean_output_dir(".bmw2");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	{
		let chain = init_chain(".bmw2", pow::mine_genesis_block().unwrap());
		let kc = ExtKeychain::from_random_seed(false).unwrap();

		// add a first block to not fork genesis
		let prev = chain.head_header().unwrap();
		let b = prepare_block(&kc, &prev, &chain, 2);
		chain.process_block(b, chain::Options::SKIP_POW).unwrap();

		// mine and add a few blocks

		for n in 1..4 {
			// first block for one branch
			let prev = chain.head_header().unwrap();
			let b1 = prepare_block(&kc, &prev, &chain, 3 * n);

			// process the first block to extend the chain
			let bhash = b1.hash();
			chain.process_block(b1, chain::Options::SKIP_POW).unwrap();

			// checking our new head
			let head = chain.head().unwrap();
			assert_eq!(head.height, (n + 1) as u64);
			assert_eq!(head.last_block_h, bhash);
			assert_eq!(head.prev_block_h, prev.hash());

			// 2nd block with higher difficulty for other branch
			let b2 = prepare_block(&kc, &prev, &chain, 3 * n + 1);

			// process the 2nd block to build a fork with more work
			let bhash = b2.hash();
			chain.process_block(b2, chain::Options::SKIP_POW).unwrap();

			// checking head switch
			let head = chain.head().unwrap();
			assert_eq!(head.height, (n + 1) as u64);
			assert_eq!(head.last_block_h, bhash);
			assert_eq!(head.prev_block_h, prev.hash());
		}
	}
	// Cleanup chain directory
	clean_output_dir(".bmw2");
}

#[test]
fn mine_losing_fork() {
	clean_output_dir(".bmw3");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();
	{
		let chain = init_chain(".bmw3", pow::mine_genesis_block().unwrap());

		// add a first block we'll be forking from
		let prev = chain.head_header().unwrap();
		let b1 = prepare_block(&kc, &prev, &chain, 2);
		let b1head = b1.header.clone();
		chain.process_block(b1, chain::Options::SKIP_POW).unwrap();

		// prepare the 2 successor, sibling blocks, one with lower diff
		let b2 = prepare_block(&kc, &b1head, &chain, 4);
		let b2head = b2.header.clone();
		let bfork = prepare_block(&kc, &b1head, &chain, 3);

		// add higher difficulty first, prepare its successor, then fork
		// with lower diff
		chain.process_block(b2, chain::Options::SKIP_POW).unwrap();
		assert_eq!(chain.head_header().unwrap().hash(), b2head.hash());
		let b3 = prepare_block(&kc, &b2head, &chain, 5);
		chain
			.process_block(bfork, chain::Options::SKIP_POW)
			.unwrap();

		// adding the successor
		let b3head = b3.header.clone();
		chain.process_block(b3, chain::Options::SKIP_POW).unwrap();
		assert_eq!(chain.head_header().unwrap().hash(), b3head.hash());
	}
	// Cleanup chain directory
	clean_output_dir(".bmw3");
}

#[test]
fn longer_fork() {
	clean_output_dir(".bmw4");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();
	// to make it easier to compute the txhashset roots in the test, we
	// prepare 2 chains, the 2nd will be have the forked blocks we can
	// then send back on the 1st
	let genesis = pow::mine_genesis_block().unwrap();
	{
		let chain = init_chain(".bmw4", genesis.clone());

		// add blocks to both chains, 20 on the main one, only the first 5
		// for the forked chain
		let mut prev = chain.head_header().unwrap();
		for n in 0..10 {
			let b = prepare_block(&kc, &prev, &chain, 2 * n + 2);
			prev = b.header.clone();
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		let forked_block = chain.get_header_by_height(5).unwrap();

		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 10);
		assert_eq!(head.hash(), prev.hash());

		let mut prev = forked_block;
		for n in 0..7 {
			let b = prepare_block(&kc, &prev, &chain, 2 * n + 11);
			prev = b.header.clone();
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		let new_head = prev;

		// After all this the chain should have switched to the fork.
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 12);
		assert_eq!(head.hash(), new_head.hash());
	}
	// Cleanup chain directory
	clean_output_dir(".bmw4");
}

#[test]
fn spend_rewind_spend() {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	util::init_test_logger();
	let chain_dir = ".bmw_spend_rewind_spend";
	clean_output_dir(chain_dir);

	{
		let chain = init_chain(chain_dir, pow::mine_genesis_block().unwrap());
		let kc = ExtKeychain::from_random_seed(false).unwrap();
		let pb = ProofBuilder::new(&kc);

		let mut head;

		// mine the first block and keep track of the block_hash
		// so we can spend the coinbase later

		let (pri_view, pub_view) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();

		let b = build_block(
			&chain,
			&kc,
			(&[]).to_vec(),
			recipient_addr,
			private_nonce.clone(),
			true,
		);
		assert!(b.outputs()[0].is_coinbase());
		head = b.header.clone();
		chain
			.process_block(b.clone(), chain::Options::SKIP_POW)
			.unwrap();

		// now mine three further blocks
		for n in 3..6 {
			let b = prepare_block(&kc, &head, &chain, n);
			head = b.header.clone();
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		// Make a note of this header as we will rewind back to here later.
		let rewind_to = head.clone();

		let index: u64 = chain.get_output_pos(&b.outputs()[0].commitment()).unwrap() - 1;
		let tx1 = build::transaction(
			KernelFeatures::Plain { fee: 20000.into() },
			&[
				build::input(consensus::REWARD1, pri_view, b.outputs()[0], index),
				build::output_rand(consensus::REWARD1 - 20000),
			],
			&kc,
			&pb,
		)
		.unwrap();

		let b = prepare_block_tx(&kc, &head, &chain, 6, &[tx1.clone()]);
		head = b.header.clone();
		chain
			.process_block(b.clone(), chain::Options::SKIP_POW)
			.unwrap();
		chain.validate(false).unwrap();

		// Now mine another block, reusing the private key for the coinbase we just spent.
		{
			let b = prepare_block_key_idx(&kc, &head, &chain, 7, 1);
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		// Now mine a competing block also spending the same coinbase output from earlier.
		// Rewind back prior to the tx that spends it to "unspend" it.
		{
			let b = prepare_block_tx(&kc, &rewind_to, &chain, 6, &[tx1]);
			chain
				.process_block(b.clone(), chain::Options::SKIP_POW)
				.unwrap();
			chain.validate(false).unwrap();
		}
	}

	clean_output_dir(chain_dir);
}

#[test]
fn spend_in_fork_and_compact() {
	clean_output_dir(".bmw6");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	util::init_test_logger();
	{
		let chain = init_chain(".bmw6", pow::mine_genesis_block().unwrap());
		let kc = ExtKeychain::from_random_seed(false).unwrap();
		let pb = ProofBuilder::new(&kc);

		let mut fork_head;

		// mine the first block and keep track of the block_hash
		// so we can spend the coinbase later
		let (pri_view, pub_view) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let (private_nonce, _pub_nonce) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();
		let b = build_block(
			&chain,
			&kc,
			(&[]).to_vec(),
			recipient_addr,
			private_nonce,
			true,
		);
		let output = b.outputs()[0];
		assert!(b.outputs()[0].is_coinbase());
		chain
			.process_block(b.clone(), chain::Options::SKIP_POW)
			.unwrap();

		let (pri_view2, pub_view2) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr2 =
			Address::from_one_pubkey(&pub_view2, global::ChainTypes::AutomatedTesting);
		let (private_nonce2, _pub_nonce2) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();
		let b = build_block(
			&chain,
			&kc,
			(&[]).to_vec(),
			recipient_addr2,
			private_nonce2,
			true,
		);
		let output2 = b.outputs()[0];
		assert!(b.outputs()[0].is_coinbase());
		fork_head = b.header.clone();
		chain
			.process_block(b.clone(), chain::Options::SKIP_POW)
			.unwrap();

		// now mine three further blocks
		for n in 3..6 {
			let b = prepare_block(&kc, &fork_head, &chain, n);
			fork_head = b.header.clone();
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		// Check the height of the "fork block".
		assert_eq!(fork_head.height, 5);

		let index1: u64 = chain.get_output_pos(&output.commitment()).unwrap() - 1;
		let index2: u64 = chain.get_output_pos(&output2.commitment()).unwrap() - 1;
		let tx1 = build::transaction(
			KernelFeatures::Plain { fee: 20000.into() },
			&[
				build::input(consensus::REWARD1, pri_view, output, index1),
				build::output_rand(consensus::REWARD1 - 20000),
			],
			&kc,
			&pb,
		)
		.unwrap();

		let next = prepare_block_tx(&kc, &fork_head, &chain, 7, &[tx1.clone()]);
		let prev_main = next.header.clone();
		chain
			.process_block(next.clone(), chain::Options::SKIP_POW)
			.unwrap();
		chain.validate(false).unwrap();

		let tx2 = build::transaction(
			KernelFeatures::Plain { fee: 20000.into() },
			&[
				build::input(consensus::REWARD1, pri_view2, output2, index2),
				build::output_rand(consensus::REWARD1 - 20000),
			],
			&kc,
			&pb,
		)
		.unwrap();

		let next = prepare_block_tx(&kc, &prev_main, &chain, 9, &[tx2.clone()]);
		let prev_main = next.header.clone();
		chain.process_block(next, chain::Options::SKIP_POW).unwrap();

		// Full chain validation for completeness.
		chain.validate(false).unwrap();

		// mine 2 forked blocks from the first
		let fork = prepare_block_tx(&kc, &fork_head, &chain, 6, &[tx1.clone()]);
		let prev_fork = fork.header.clone();
		chain.process_block(fork, chain::Options::SKIP_POW).unwrap();

		let fork_next = prepare_block_tx(&kc, &prev_fork, &chain, 8, &[tx2.clone()]);
		let prev_fork = fork_next.header.clone();
		chain
			.process_block(fork_next, chain::Options::SKIP_POW)
			.unwrap();

		chain.validate(false).unwrap();

		// check state
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 7);
		assert_eq!(head.hash(), prev_main.hash());
		assert!(chain
			.get_unspent(tx2.outputs()[0].commitment())
			.unwrap()
			.is_some());
		assert!(chain
			.get_unspent(tx1.outputs()[0].commitment())
			.unwrap()
			.is_some());

		// make the fork win
		let fork_next = prepare_block(&kc, &prev_fork, &chain, 10);
		let prev_fork = fork_next.header.clone();
		chain
			.process_block(fork_next, chain::Options::SKIP_POW)
			.unwrap();
		chain.validate(false).unwrap();

		// check state
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 8);
		assert_eq!(head.hash(), prev_fork.hash());
		assert!(chain
			.get_unspent(tx2.outputs()[0].commitment())
			.unwrap()
			.is_some());
		assert!(chain
			.get_unspent(tx1.outputs()[0].commitment())
			.unwrap()
			.is_some());

		// add 20 blocks to go past the test horizon
		let mut prev = prev_fork;
		for n in 0..20 {
			let next = prepare_block(&kc, &prev, &chain, 11 + n);
			prev = next.header.clone();
			chain.process_block(next, chain::Options::SKIP_POW).unwrap();
		}

		chain.validate(false).unwrap();
		if let Err(e) = chain.compact() {
			panic!("Error compacting chain: {:?}", e);
		}
		if let Err(e) = chain.validate(false) {
			panic!("Validation error after compacting chain: {:?}", e);
		}
	}
	// Cleanup chain directory
	clean_output_dir(".bmw6");
}

/// Test ability to retrieve block headers for a given output
#[test]
fn output_header_mappings() {
	clean_output_dir(".bmw_header_for_output");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	util::init_test_logger();
	{
		let chain = init_chain(".bmw_header_for_output", pow::mine_genesis_block().unwrap());
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let mut reward_outputs = vec![];

		for n in 1..15 {
			let prev = chain.head_header().unwrap();
			let next_header_info =
				consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());

			let (private_nonce, _pub_nonce) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let (_pri_view, pub_view) =
				keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
			let recipient_addr =
				Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

			let reward = libtx::reward::nit_output(
				&keychain,
				&libtx::ProofBuilder::new(&keychain),
				private_nonce,
				recipient_addr,
				PaymentId::new(),
				0,
				false,
				prev.height + 1,
			)
			.unwrap();
			reward_outputs.push(reward.0.clone());
			let mut b = core::core::Block::new(
				&prev,
				&[],
				next_header_info.clone().difficulty,
				reward,
				None,
			)
			.unwrap();
			b.header.timestamp = prev.timestamp + Duration::seconds(60);
			b.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&mut b).unwrap();

			let edge_bits = if n == 2 {
				global::min_edge_bits() + 1
			} else {
				global::min_edge_bits()
			};
			b.header.pow.proof.edge_bits = edge_bits;
			pow::pow_size(
				&mut b.header,
				next_header_info.difficulty,
				global::proofsize(),
				edge_bits,
			)
			.unwrap();
			b.header.pow.proof.edge_bits = edge_bits;

			chain.process_block(b, chain::Options::MINE).unwrap();

			let header_for_output = chain
				.get_header_for_output(reward_outputs[n - 1].commitment())
				.unwrap();
			assert_eq!(header_for_output.height, n as u64);

			chain.validate(false).unwrap();
		}

		// Check all output positions are as expected
		for n in 1..15 {
			let header_for_output = chain
				.get_header_for_output(reward_outputs[n - 1].commitment())
				.unwrap();
			assert_eq!(header_for_output.height, n as u64);
		}
	}
	// Cleanup chain directory
	clean_output_dir(".bmw_header_for_output");
}

/// Test the duplicate rangeproof bug
#[test]
fn test_overflow_cached_rangeproof() {
	util::init_test_logger();
	let chain_dir = ".grin_overflow";
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
		let last_rp = coinbase_txn.outputs()[0].proof;

		let next_input = coinbase_txn.outputs()[0];

		coinbase_txn
			.validate(
				Weighting::AsTransaction,
				verifier_cache.clone(),
				0,
				None,
				None,
			)
			.unwrap();
		chain.validate_tx(&coinbase_txn).unwrap();

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

		assert_eq!(chain.head_header().unwrap().height, 5);

		// create a second tx that contains a negative output
		// and a positive output for 1m grin
		let index: u64 = chain.get_output_pos(&next_input.commitment()).unwrap() - 1;
		let mut tx2 = build::transaction(
			KernelFeatures::Plain { fee: 0.into() },
			&[
				build::input(consensus::REWARD1 - 2, pri_view3, next_input, index),
				build::output_rand(consensus::REWARD1 - 20000 + 1_000_000_000_000_000),
				build::output_negative(1_000_000_000_000_000, recipient_addr),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		// overwrite all our rangeproofs with the rangeproof from last block
		for i in 0..tx2.body.outputs.len() {
			tx2.body.outputs[i].proof = last_rp;
		}

		let res = tx2.validate(
			Weighting::AsTransaction,
			verifier_cache.clone(),
			0,
			None,
			None,
		);
		assert_eq!(format!("{:?}", res).contains("InvalidRangeProof"), true);
	}
	clean_output_dir(".grin_overflow");
}

/// Test a reorg claim
#[test]
fn test_reorg_claims_x() -> Result<(), Error> {
	// Test configuration
	const NUM_BLOCKS_MAIN: u64 = 6; // Number of blocks to mine in main chain
	const REORG_DEPTH: u64 = 5; // Number of blocks to be discarded from main chain after reorg

	const DIR_NAME: &str = ".bmw_reorg2";
	clean_output_dir(DIR_NAME);

	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();

	// build claim tx
	let binary_location = "./tests/resources/gen_bin1.bin";
	let keychain = ExtKeychain::from_seed(&[0; 32], true).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let mut utxo_data = UtxoData::new(ChainType::Bypass).unwrap();
	utxo_data.load_binary(binary_location)?;
	let utxo_data = Arc::new(RwLock::new(utxo_data));

	let mut sig_vec = Vec::new();
	let mut rec_id_vec = Vec::new();
	let signatures = vec![
		"IBhOFbM5gg+HBTL0tTxgO1a9fTuO+gTuRAyaBJ9jmeLnDFTTii6yINcFeOJ6m2pO/cN12Bg971n5aS5EbUTQs/c="
			.to_string(),
	];
	let fee = 100;
	let amount = 100_000_000_000_000;
	let index = 0;
	for sig in signatures {
		let signature = base64::decode(sig).unwrap();
		let recid = RecoveryId::from_i32(i32::from((signature[0] - 27) & 3)).unwrap();
		let recsig = RecoverableSignature::from_compact(&signature[1..], recid).unwrap();
		sig_vec.push(recsig);
		rec_id_vec.push(signature[0]);
	}

	let pri_view = SecretKey::from_slice(
		&keychain.secp(),
		&[
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			1 + index as u8,
		],
	)
	.unwrap();
	let pub_view = PublicKey::from_secret_key(keychain.secp(), &pri_view).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let (out, kern) = reward::output_btc_claim(
		&keychain,
		&builder,
		recipient_addr,
		fee,
		true,
		amount,
		index,
		sig_vec.clone(),
		rec_id_vec.clone(),
		None,
		0,
		Some(pri_view),
		PaymentId::new(),
	)
	.unwrap();

	let tx1 = Transaction {
		offset: BlindingFactor::zero(),
		body: TransactionBody {
			inputs: Inputs(Vec::new()),
			outputs: vec![out],
			kernels: vec![kern],
		},
	};

	let fee = 101;

	let signatures = vec![
		"IEcBejZXsar/M7ovQD3yF3auTAmyLmmb+SBp/Eyh7v8iTjI8s+fKFET2PihJgUneHtRDDiZcj8aFx+DKJ3x1BcI="
			.to_string(),
	];

	let mut sig_vec = Vec::new();
	let mut rec_id_vec = Vec::new();

	for sig in signatures {
		let signature = base64::decode(sig).unwrap();
		let recid = RecoveryId::from_i32(i32::from((signature[0] - 27) & 3)).unwrap();
		let recsig = RecoverableSignature::from_compact(&signature[1..], recid).unwrap();
		sig_vec.push(recsig);
		rec_id_vec.push(signature[0]);
	}

	let pri_view = SecretKey::from_slice(
		&keychain.secp(),
		&[
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			1 + index as u8,
		],
	)
	.unwrap();
	let pub_view = PublicKey::from_secret_key(keychain.secp(), &pri_view).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let (out, kern) = reward::output_btc_claim(
		&keychain,
		&builder,
		recipient_addr,
		fee,
		true,
		amount,
		index,
		sig_vec,
		rec_id_vec,
		None,
		0,
		Some(pri_view),
		PaymentId::new(),
	)
	.unwrap();

	let tx2 = Transaction {
		offset: BlindingFactor::zero(),
		body: TransactionBody {
			inputs: Inputs(Vec::new()),
			outputs: vec![out],
			kernels: vec![kern],
		},
	};

	let valid = tx1.validate(
		Weighting::AsTransaction,
		verifier_cache(),
		100,
		Some(Arc::downgrade(&utxo_data)),
		None,
	);

	assert_eq!(valid.is_ok(), true);

	let valid = tx2.validate(
		Weighting::AsTransaction,
		verifier_cache(),
		101,
		Some(Arc::downgrade(&utxo_data)),
		None,
	);

	assert_eq!(valid.is_ok(), true);

	let genesis = pow::mine_genesis_block().unwrap();
	{
		// Create chain that reports last block status
		let last_status = RwLock::new(None);
		let adapter = Arc::new(StatusAdapter::new(last_status));
		let chain = setup_with_status_adapter(
			DIR_NAME,
			genesis.clone(),
			adapter.clone(),
			Some(Arc::downgrade(&utxo_data)),
		);

		// Add blocks to main chain with gradually increasing difficulty
		let mut prev = chain.head_header().unwrap();
		for n in 1..=NUM_BLOCKS_MAIN {
			let b = if n == NUM_BLOCKS_MAIN - 1 {
				prepare_block_tx(&kc, &prev, &chain, n, &[tx1.clone()])
			} else {
				prepare_block(&kc, &prev, &chain, n)
			};
			prev = b.header.clone();
			chain.process_block(b, chain::Options::SKIP_POW).unwrap();
		}

		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN);
		assert_eq!(head.hash(), prev.hash());

		// Reorg chain should exceed main chain's total difficulty to be considered
		// but first a small block
		let fork_head = chain
			.get_header_by_height(NUM_BLOCKS_MAIN - REORG_DEPTH)
			.unwrap();
		let b = prepare_block(&kc, &fork_head, &chain, 2);
		chain
			.process_block(b.clone(), chain::Options::SKIP_POW)
			.unwrap();
		let reorg_difficulty = head.total_difficulty.to_num();

		let b = prepare_block_tx(
			&kc,
			&b.header.clone(),
			&chain,
			reorg_difficulty,
			&[tx1.clone()],
		);
		let reorg_head = b.header.clone();
		chain
			.process_block(b.clone(), chain::Options::SKIP_POW)
			.unwrap();

		// Chain should be switched to the reorganized chain
		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN - REORG_DEPTH + 2);
		assert_eq!(head.hash(), reorg_head.hash());

		// try to process with the same tx again, should fail...
		let prev = b.header.clone();
		let b = prepare_block_tx(&kc, &prev, &chain, reorg_difficulty, &[tx2.clone()]);
		let res = chain.process_block(b.clone(), chain::Options::SKIP_POW);
		// this is an error because this one was already claimed.
		assert_eq!(res.is_err(), true);
	}

	// Cleanup chain directory
	clean_output_dir(DIR_NAME);
	Ok(())
}

/// Test a fork claim
#[test]
fn test_reorg_claims_advanced() -> Result<(), Error> {
	// Test configuration
	const NUM_BLOCKS_MAIN: u64 = 5; // Number of blocks to mine in main chain
	const REORG_DEPTH: u64 = 3; // Number of blocks to be discarded from main chain after reorg

	const DIR_NAME: &str = ".bmw_reorg_adv";
	clean_output_dir(DIR_NAME);

	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let kc = ExtKeychain::from_random_seed(false).unwrap();

	let binary_location = "./tests/resources/gen_bin2.bin";
	let mut utxo_data = UtxoData::new(ChainType::Bypass).unwrap();
	utxo_data.load_binary(binary_location)?;
	let utxo_data = Arc::new(RwLock::new(utxo_data));

	// build transactions
	let tx0_a = build_claim_txn(
		100,
		100_000_000_000,
		0,
		"HwdEbVUN0QLOWkJ11sc3acMTS0wnAhwmP5tUuCwxhx0kb5goIWVpmZTpiBjgQYJuShNVHKQXMri6zl2IAJBh6q0=",
		utxo_data.clone(),
	)?;

	let tx0_b = build_claim_txn(
		101,
		100_000_000_000,
		0,
		"IF82vJiW2du92ojfnVk1pJEvoCdFiASEd33tIKlDqD7paLTwgRI8x2btvh1TMAHiLDLcVzbOjif5Qr1ivy+kAGc=",
		utxo_data.clone(),
	)?;

	let tx1_a = build_claim_txn(
		100,
		100_000_000_000,
		1,
		"HyfhpVuVqxH31y7o9ZjehwCFVmulUhSqCl5ouJcFHd/7N4sjJrmVrcICjRuz+5eDRhD2b7bT5rQA0U/612xjAek=",
		utxo_data.clone(),
	)?;

	let tx1_b = build_claim_txn(
		101,
		100_000_000_000,
		1,
		"IDbOlBhjzZTQS1kmNNbmz3LdHRYx0MS20C9WFDFlHL79b7r38P9mQB4dkgoYbW42uJJxm+vSAlIXPwPvtZVRrxk=",
		utxo_data.clone(),
	)?;

	let tx2_a = build_claim_txn(
		100,
		100_000_000_000,
		2,
		"HyQRWGOtxZVu8gybyV3FR35lQXP/gtFkUjkvEFm03X6bbyg9uUFgYFKoFX4Bno+2Kr41/QXw0Qc0ES1l7+KTcAY=",
		utxo_data.clone(),
	)?;

	let tx2_b = build_claim_txn(
		101,
		100_000_000_000,
		2,
		"H0S0kJs3JwE24ufoAFgfhgy/b+PHyy/iaYvBzpqvVI8UcnMS/6QVLtL3hVETRKqkMNaIdXUqLmmNm5PNidMQIgU=",
		utxo_data.clone(),
	)?;

	let tx3_a = build_claim_txn(
		100,
		100_000_000_000,
		3,
		"IEqPFYohBuAxJq+dAsuUByyCd8QbyncU0Lsvn2JUBTJbCkuSCldbrqKFRpre0SZEyEeU7GRD7sPNdN7RvYmlpLg=",
		utxo_data.clone(),
	)?;

	let tx3_b = build_claim_txn(
		101,
		100_000_000_000,
		3,
		"IFDmDOeo9zv7A7nxz/xndlk9+2ISfBfJWOJKVidfg0l9M8feUyJ9iuEHT30Yoi8e80k4YuHEYops9ppoWmikhFU=",
		utxo_data.clone(),
	)?;

	let tx4_a = build_claim_txn(
		100,
		100_000_000_000,
		4,
		"IA7xYLoa7ZZIWh79WCsCiiH8wOg2d52yog3z2G3qa/gCP7IslWYZftq7cMUI8qRtoZeG8DoCLui2zh8N7S0Yw7g=",
		utxo_data.clone(),
	)?;

	let tx4_b = build_claim_txn(
		101,
		100_000_000_000,
		4,
		"IGAv805qKawuBiSZK3ivKDjvxDlVlV/Soq0BC/mPeCbgQECvD+bePW981luqeUcM9QcM08gNFIxtKEmp4GSApdA=",
		utxo_data.clone(),
	)?;

	let tx5_a = build_claim_txn(
		100,
		100_000_000_000,
		5,
		"IADMGQWigH+KDQEy0Jw9YDemQhM0i+pJCEQQY6kyxC5EWetnX6B8WkuDHZ81NjTAxP6j/Q8NT3J6DcA+xUjftoo=",
		utxo_data.clone(),
	)?;

	let tx5_b = build_claim_txn(
		101,
		100_000_000_000,
		5,
		"IAlbQfcUwrhvS/pR0CI8XnJbj/mPnGmTl2n8iTvgRpV8c2cbSZygQftmTPZRqfaHN6Omli7XBzy+pXkawg11JjE=",
		utxo_data.clone(),
	)?;

	let genesis = pow::mine_genesis_block().unwrap();
	{
		// Create chain that reports last block status
		let last_status = RwLock::new(None);
		let adapter = Arc::new(StatusAdapter::new(last_status));
		let chain = setup_with_status_adapter(
			DIR_NAME,
			genesis.clone(),
			adapter.clone(),
			Some(Arc::downgrade(&utxo_data)),
		);

		// Add blocks to main chain with gradually increasing difficulty
		let mut prev = chain.head_header().unwrap();
		let mut last = prev.clone();
		for n in 1..=NUM_BLOCKS_MAIN {
			let b = if n == 1 {
				prep_and_mine(&kc, &prev, &chain, n, &[tx0_a.clone()], true)
			} else if n == 2 {
				prep_and_mine(&kc, &prev, &chain, n, &[tx1_a.clone()], true)
			} else if n == 3 {
				prep_and_mine(&kc, &prev, &chain, n, &[tx2_a.clone()], true)
			} else if n == 4 {
				prep_and_mine(&kc, &prev, &chain, n, &[tx3_a.clone()], true)
			} else
			/* n == 5 */
			{
				prep_and_mine(&kc, &prev, &chain, n, &[tx4_a.clone()], true)
			};
			prev = b.header.clone();
			last = prev.clone();
		}

		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN);
		assert_eq!(head.hash(), prev.hash());

		let fork_head = chain
			.get_header_by_height(NUM_BLOCKS_MAIN - REORG_DEPTH)
			.unwrap();

		// try some invalid blocks
		prep_and_mine(
			&kc,
			&fork_head,
			&chain,
			3,
			&[tx0_b.clone(), tx1_b.clone()],
			false,
		);

		prep_and_mine(
			&kc,
			&fork_head,
			&chain,
			3,
			&[tx0_b.clone(), tx1_b.clone(), tx4_b.clone()],
			false,
		);

		prep_and_mine(&kc, &fork_head, &chain, 3, &[tx0_b.clone()], false);

		prep_and_mine(&kc, &fork_head, &chain, 3, &[tx1_b.clone()], false);

		prep_and_mine(
			&kc,
			&fork_head,
			&chain,
			3,
			&[tx0_b.clone(), tx4_b.clone()],
			false,
		);

		// finally do the valid one
		let b = prep_and_mine(&kc, &fork_head, &chain, 3, &[tx4_b.clone()], true);

		// old chain should still be head
		assert_eq!(chain.head().unwrap(), Tip::from_header(&last));

		// try some invalid blocks
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			4,
			&[tx0_b.clone(), tx4_b.clone()],
			false,
		);
		prep_and_mine(&kc, &b.header, &chain, 4, &[tx4_b.clone()], false);
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			4,
			&[tx1_b.clone(), tx4_b.clone()],
			false,
		);
		prep_and_mine(&kc, &b.header, &chain, 4, &[tx0_b.clone()], false);
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			4,
			&[tx0_b.clone(), tx2_b.clone()],
			false,
		);
		// finally do the valid one
		let b = prep_and_mine(&kc, &b.header, &chain, 4, &[tx2_b.clone()], true);

		// old chain should still be head
		assert_eq!(chain.head().unwrap(), Tip::from_header(&last));

		// try some invalid blocks
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			100,
			&[tx0_b.clone(), tx5_a.clone()],
			false,
		);
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			100,
			&[tx0_b.clone(), tx5_b.clone()],
			false,
		);
		prep_and_mine(&kc, &b.header, &chain, 100, &[tx0_b.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 100, &[tx2_a.clone()], false);
		// finally do the valid one
		let b = prep_and_mine(&kc, &b.header, &chain, 100, &[], true);
		// now the reorg has completed because there's more work.
		assert_eq!(chain.head().unwrap(), Tip::from_header(&b.header));

		// mine a few more blocks
		let b = prep_and_mine(&kc, &b.header, &chain, 200, &[], true);
		let b = prep_and_mine(&kc, &b.header, &chain, 300, &[], true);
		let b = prep_and_mine(&kc, &b.header, &chain, 400, &[], true);

		// do some invalid blocks
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx2_a.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx0_a.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx0_b.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx1_a.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx1_b.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx2_a.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx2_b.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx4_a.clone()], false);
		prep_and_mine(&kc, &b.header, &chain, 101, &[tx4_b.clone()], false);
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			101,
			&[tx0_a.clone(), tx1_b.clone()],
			false,
		);
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			101,
			&[tx0_b.clone(), tx3_b.clone()],
			false,
		);
		prep_and_mine(
			&kc,
			&b.header,
			&chain,
			101,
			&[tx1_b.clone(), tx3_b.clone(), tx5_b.clone()],
			false,
		);

		// finally do the valid one
		let b = prep_and_mine(
			&kc,
			&b.header,
			&chain,
			101,
			&[tx3_b.clone(), tx5_a.clone()],
			true,
		);
		// still should be the tip of the chain
		assert_eq!(chain.head().unwrap(), Tip::from_header(&b.header));
	}

	// Cleanup chain directory
	clean_output_dir(DIR_NAME);

	Ok(())
}

fn build_claim_txn(
	fee: u64,
	amount: u64,
	index: u32,
	signature: &str,
	utxo_data: Arc<RwLock<UtxoData>>,
) -> Result<Transaction, Error> {
	let keychain = ExtKeychain::from_seed(&[0; 32], true).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let mut sig_vec = Vec::new();
	let mut rec_id_vec = Vec::new();
	let signatures = vec![signature];

	for sig in signatures {
		let signature = base64::decode(sig).unwrap();
		let recid = RecoveryId::from_i32(i32::from((signature[0] - 27) & 3)).unwrap();
		let recsig = RecoverableSignature::from_compact(&signature[1..], recid).unwrap();
		sig_vec.push(recsig);
		rec_id_vec.push(signature[0]);
	}

	let pri_view = SecretKey::from_slice(
		&keychain.secp(),
		&[
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			1 + index as u8,
		],
	)
	.unwrap();
	let pub_view = PublicKey::from_secret_key(keychain.secp(), &pri_view).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let (out, kern) = reward::output_btc_claim(
		&keychain,
		&builder,
		recipient_addr,
		fee,
		true,
		amount,
		index,
		sig_vec.clone(),
		rec_id_vec.clone(),
		None,
		0,
		Some(pri_view),
		PaymentId::new(),
	)
	.unwrap();

	let tx = Transaction {
		offset: BlindingFactor::zero(),
		body: TransactionBody {
			inputs: Inputs(Vec::new()),
			outputs: vec![out],
			kernels: vec![kern],
		},
	};

	tx.validate(
		Weighting::AsTransaction,
		verifier_cache(),
		0,
		Some(Arc::downgrade(&utxo_data)),
		None,
	)?;

	Ok(tx)
}

fn prep_and_mine<K>(
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	txs: &[Transaction],
	valid: bool,
) -> Block
where
	K: Keychain,
{
	//let b = prepare_block_tx(kc, &prev, &chain, difficulty, txs);
	//let b = prepare_block_tx_key_idx(kc, prev, chain, diff, diff as u32, txs);

	let mut b = prepare_block_nosum(kc, prev, diff, diff as u32, txs);
	let res = chain.set_txhashset_roots(&mut b);

	if valid {
		res.unwrap();
	}

	let res = chain.process_block(b.clone(), chain::Options::SKIP_POW);
	assert_eq!(res.is_ok(), valid);
	if res.is_ok() {
		res.unwrap();
	}
	b
}

// Use diff as both diff *and* key_idx for convenience (deterministic private key for test blocks)
fn prepare_block<K>(kc: &K, prev: &BlockHeader, chain: &Chain, diff: u64) -> Block
where
	K: Keychain,
{
	let key_idx = diff as u32;
	prepare_block_key_idx(kc, prev, chain, diff, key_idx)
}

fn prepare_block_key_idx<K>(
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	key_idx: u32,
) -> Block
where
	K: Keychain,
{
	let mut b = prepare_block_nosum(kc, prev, diff, key_idx, &[]);
	chain.set_txhashset_roots(&mut b).unwrap();
	b
}

// Use diff as both diff *and* key_idx for convenience (deterministic private key for test blocks)
fn prepare_block_tx<K>(
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	txs: &[Transaction],
) -> Block
where
	K: Keychain,
{
	let key_idx = diff as u32;
	prepare_block_tx_key_idx(kc, prev, chain, diff, key_idx, txs)
}

fn prepare_block_tx_key_idx<K>(
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	key_idx: u32,
	txs: &[Transaction],
) -> Block
where
	K: Keychain,
{
	let mut b = prepare_block_nosum(kc, prev, diff, key_idx, txs);
	let res = chain.set_txhashset_roots(&mut b);
	res.unwrap();
	b
}

fn prepare_block_nosum<K>(
	kc: &K,
	prev: &BlockHeader,
	diff: u64,
	_key_idx: u32,
	txs: &[Transaction],
) -> Block
where
	K: Keychain,
{
	let proof_size = global::proofsize();
	let (_pri_view, pub_view) = kc.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	let mut b = new_block(txs, kc, &ProofBuilder::new(kc), &prev, recipient_addr);
	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.total_difficulty = prev.total_difficulty() + Difficulty::from_num(diff);
	b.header.pow.proof = pow::Proof::random(proof_size);
	b
}

#[test]
#[ignore]
fn actual_diff_iter_output() {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	let genesis_block = pow::mine_genesis_block().unwrap();
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
	let chain = chain::Chain::init(
		"../.bmw".to_string(),
		Arc::new(NoopAdapter {}),
		genesis_block,
		pow::verify_size,
		verifier_cache,
		false,
		None,
	)
	.unwrap();
	let iter = chain.difficulty_iter().unwrap();
	let mut last_time = 0;
	let mut first = true;
	for elem in iter.into_iter() {
		if first {
			last_time = elem.timestamp;
			first = false;
		}
		println!(
			"next_difficulty time: {}, diff: {}, duration: {} ",
			elem.timestamp,
			elem.difficulty.to_num(),
			last_time - elem.timestamp
		);
		last_time = elem.timestamp;
	}
}
