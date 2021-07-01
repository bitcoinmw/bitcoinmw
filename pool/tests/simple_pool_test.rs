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

pub mod common;

use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::pool::PoolError;
use self::util::RwLock;
use crate::common::*;
use grin_core as core;
use grin_core::core::Transaction;
use grin_keychain as keychain;
use grin_pool as pool;
use grin_util as util;
use std::sync::Arc;

#[test]
fn test_simple_pool() -> Result<(), PoolError> {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(0);
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = "target/.block_building";
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

	// mine some blocks
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
		vec![100, 2, 30, 40, 44, 47],
	);

	// Mine that initial tx so we can spend it with multiple txs.
	add_block(&chain, &[initial_tx], &keychain);

	let header = chain.head_header().unwrap();

	// get the input signature in this transaction to use in the next transaction
	// this also exercises the input_sig cache
	let prev_input_sig = chain.get_block(&header.hash()).unwrap().inputs().0[0].sig;

	let root_tx_1 = test_transaction(&keychain, vec![100, 2], vec![24], &chain);
	let root_tx_2 = test_transaction(&keychain, vec![40], vec![25], &chain);

	// make the second transaction have a bad input_signature
	let mut inputs = root_tx_2.inputs();
	let mut bad_tx2 = Transaction::empty();
	inputs.0[0].sig = prev_input_sig;
	bad_tx2.body = root_tx_2.body.replace_inputs(inputs);

	{
		// Add the first root tx to the pool.
		pool.add_to_pool(test_source(), root_tx_1.clone(), false, &header)?;
		assert_eq!(pool.total_size(), 1);

		// try to add the invalid transaction
		let res = pool.add_to_pool(test_source(), bad_tx2.clone(), false, &header);
		assert_eq!(res.is_err(), true);
		assert_eq!(pool.total_size(), 1);
	}

	let txs = pool.prepare_mineable_transactions()?;
	add_block(&chain, &txs, &keychain);

	// Get full block from head of the chain (block we just processed).
	let block = chain.get_block(&chain.head().unwrap().hash()).unwrap();

	// Check the block contains what we expect.
	assert_eq!(block.inputs().len(), 2);
	assert_eq!(block.outputs().len(), 2);
	assert_eq!(block.kernels().len(), 2);

	assert!(block.kernels().contains(&root_tx_1.kernels()[0]));

	// Now reconcile the transaction pool with the new block
	// and check the resulting contents of the pool are what we expect.
	{
		pool.reconcile_block(&block)?;
		assert_eq!(pool.total_size(), 0);
	}

	// Cleanup db directory
	clean_output_dir(db_root.into());

	Ok(())
}
