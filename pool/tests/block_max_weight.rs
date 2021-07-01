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

//! Test coverage for block building at the limit of max_block_weight.

pub mod common;
use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::util::RwLock;
use crate::common::*;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;
use std::sync::Arc;

#[test]
fn test_block_building_max_weight() {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(0);

	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = "target/.block_max_weight";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(db_root, genesis));
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(
		Arc::new(ChainAdapter {
			chain: chain.clone(),
		}),
		verifier_cache,
	);

	// mine past HF4 to see effect of set_local_accept_fee_base
	add_some_blocks(&chain, 4, &keychain);

	let header_1 = chain.get_header_by_height(1).unwrap();
	let block_1 = chain.get_block(&header_1.hash()).unwrap();
	let output = block_1.outputs()[0];
	let index: u64 = chain.get_output_pos(&output.commitment()).unwrap() - 1;

	// Now create tx to spend an early coinbase (now matured).
	// Provides us with some useful outputs to test with.
	let initial_tx = test_transaction_spending_coinbase(
		&keychain,
		&header_1,
		output,
		index,
		vec![101, 102, 103, 104],
	);

	// Mine that initial tx so we can spend it with multiple txs.
	add_block(&chain, &[initial_tx], &keychain);

	// get a second layer of txns
	let header_2 = chain.get_header_by_height(2).unwrap();
	let block_2 = chain.get_block(&header_2.hash()).unwrap();
	let output = block_2.outputs()[0];
	let index: u64 = chain.get_output_pos(&output.commitment()).unwrap() - 1;
	let second_tx = test_transaction_spending_coinbase(
		&keychain,
		&header_2,
		output,
		index,
		vec![105, 106, 107, 108],
	);

	// Mine that second tx so we can spend it with multiple txs.
	add_block(&chain, &[second_tx], &keychain);

	let header = chain.head_header().unwrap();

	// Build some dependent txs to add to the txpool.
	// We will build a block from a subset of these.
	let txs = vec![
		test_transaction(&keychain, vec![101], vec![10, 11], &chain),
		test_transaction(&keychain, vec![102], vec![12, 13], &chain),
		test_transaction(&keychain, vec![103], vec![14, 15], &chain),
		test_transaction(&keychain, vec![104], vec![16], &chain),
		test_transaction(&keychain, vec![105], vec![17, 18, 19], &chain),
		test_transaction(&keychain, vec![106], vec![20, 21, 22], &chain),
		test_transaction(&keychain, vec![107], vec![23, 24, 25], &chain),
		test_transaction(&keychain, vec![108], vec![26], &chain),
	];

	// Fees and weights of our original txs in insert order.
	assert_eq!(
		txs.iter().map(|x| x.fee(header.height)).collect::<Vec<_>>(),
		[80, 77, 74, 88, 51, 43, 35, 82]
	);
	assert_eq!(
		txs.iter().map(|x| x.weight()).collect::<Vec<_>>(),
		[46, 46, 46, 25, 67, 67, 67, 25]
	);

	assert_eq!(
		txs.iter()
			.map(|x| x.fee_rate(header.height))
			.collect::<Vec<_>>(),
		[1, 1, 1, 3, 0, 0, 0, 3]
	);

	// Populate our txpool with the txs.
	for tx in txs {
		pool.add_to_pool(test_source(), tx, false, &header).unwrap();
	}

	// Check we added them all to the txpool successfully.
	assert_eq!(pool.total_size(), 8);

	// // Prepare some "mineable" txs from the txpool.
	// // Note: We cannot fit all the txs from the txpool into a block.
	let txs = pool.prepare_mineable_transactions().unwrap();

	// Fees and weights of the "mineable" txs.
	assert_eq!(
		txs.iter().map(|x| x.fee(header.height)).collect::<Vec<_>>(),
		[88, 82, 80, 77, 74]
	);
	assert_eq!(
		txs.iter().map(|x| x.weight()).collect::<Vec<_>>(),
		[25, 25, 46, 46, 46]
	);
	assert_eq!(
		txs.iter()
			.map(|x| x.fee_rate(header.height))
			.collect::<Vec<_>>(),
		[3, 3, 1, 1, 1]
	);

	add_block(&chain, &txs, &keychain);
	let block = chain.get_block(&chain.head().unwrap().hash()).unwrap();

	// Check contents of the block itself (including coinbase reward).
	assert_eq!(block.inputs().len(), 5);
	assert_eq!(block.outputs().len(), 9);
	assert_eq!(block.kernels().len(), 6);

	// Now reconcile the transaction pool with the new block
	// and check the resulting contents of the pool are what we expect.
	pool.reconcile_block(&block).unwrap();

	// We should still have 3 tx in the pool after accepting the new block.
	// This one exceeded the max block weight when building the block so
	// remained in the txpool.
	assert_eq!(pool.total_size(), 3);

	// Cleanup db directory
	clean_output_dir(db_root.into());
}
