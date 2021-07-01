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

// Note: This test has changed quite a bit since transactions that are not
// confirmed cannot be mined anymore. It's somewhat simple now.
// would be good to extend it if there is anything else that needs to be covered.

pub mod common;

use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::util::RwLock;
use crate::common::ChainAdapter;
use crate::common::*;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;
use std::sync::Arc;

#[test]
fn test_transaction_pool_block_reconciliation() {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(0);
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = "target/.block_reconciliation";
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

	// mine some blocks so we can spend a coinbase
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
		vec![10, 20, 30, 40],
	);

	// Mine that initial tx so we can spend it with multiple txs.
	add_block(&chain, &[initial_tx], &keychain);

	let header = chain.head_header().unwrap();

	let tx1 = test_transaction(&keychain, vec![10], vec![1], &chain);
	let tx2 = test_transaction(&keychain, vec![10], vec![2], &chain);
	let tx3 = test_transaction(&keychain, vec![20], vec![3], &chain);
	let tx4 = test_transaction(&keychain, vec![30], vec![4], &chain);
	let tx5 = test_transaction(&keychain, vec![40], vec![5], &chain);

	// pool empty
	assert_eq!(pool.total_size(), 0);

	// add tx1 and tx3 to the pool
	pool.add_to_pool(test_source(), tx1.clone(), false, &header)
		.unwrap();
	pool.add_to_pool(test_source(), tx3.clone(), false, &header)
		.unwrap();
	pool.add_to_pool(test_source(), tx4.clone(), false, &header)
		.unwrap();
	pool.add_to_pool(test_source(), tx5.clone(), false, &header)
		.unwrap();

	// mine a block with tx2
	add_block(&chain, &[tx2], &keychain);
	let block = chain.get_block(&chain.head().unwrap().hash()).unwrap();

	// Check the pool still contains everything we expect at this point.
	assert_eq!(pool.total_size(), 4);

	// And reconcile the pool with this latest block.
	pool.reconcile_block(&block).unwrap();

	// Check the pool still contains everything we expect at this point.
	assert_eq!(pool.total_size(), 3);

	// do some checks on kernels
	assert_eq!(pool.txpool.entries[0].tx.kernels(), tx3.kernels());
	assert_eq!(pool.txpool.entries[1].tx.kernels(), tx4.kernels());
	assert_eq!(pool.txpool.entries[2].tx.kernels(), tx5.kernels());

	// Cleanup db directory
	clean_output_dir(db_root.into());
}
