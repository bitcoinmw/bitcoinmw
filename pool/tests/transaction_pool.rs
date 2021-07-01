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

use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::{transaction, Weighting};
use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::pool::PoolError;
use self::pool::TxSource;
use self::util::RwLock;
use crate::common::*;
use grin_core as core;
use grin_core::core::hash::Hashed;
use grin_keychain as keychain;
use grin_pool as pool;
use grin_util as util;
use std::sync::Arc;

/// Test we can add some txs to the pool (both stempool and txpool).
#[test]
fn test_the_transaction_pool() -> Result<(), PoolError> {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(0);
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = "target/.transaction_pool";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(db_root, genesis));
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(
		Arc::new(ChainAdapter {
			chain: chain.clone(),
		}),
		verifier_cache.clone(),
	);

	// mine to use coinbases
	add_some_blocks(&chain, 4, &keychain);
	let header = chain.head_header().unwrap();

	let header_1 = chain.get_header_by_height(1).unwrap();
	let block_1 = chain.get_block(&header_1.hash()).unwrap();
	let output = block_1.outputs()[0];
	let index: u64 = chain.get_output_pos(&output.commitment()).unwrap() - 1;
	let initial_tx = test_transaction_spending_coinbase(
		&keychain,
		&header_1,
		output,
		index,
		vec![105, 106, 107, 108, 109, 110, 111, 112, 113, 114],
	);

	// Add this tx to the pool (stem=false, direct to txpool).
	{
		pool.add_to_pool(test_source(), initial_tx, false, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 1);
	}

	// Test adding a tx that "double spends" an output currently spent by a tx
	// already in the txpool. In this case we attempt to spend the original coinbase twice.
	{
		let block_1 = chain.get_block(&header.hash()).unwrap();
		let output = block_1.outputs()[0];
		let index: u64 = chain.get_output_pos(&output.commitment()).unwrap() - 1;
		let tx = test_transaction_spending_coinbase(&keychain, &header, output, index, vec![501]);
		assert!(pool.add_to_pool(test_source(), tx, false, &header).is_err());
	}

	let txs = pool.prepare_mineable_transactions()?;
	add_block(&chain, &txs, &keychain);
	let block = chain.get_block(&chain.head_header()?.hash()).unwrap();

	// Now reconcile the transaction pool with the new block
	// and check the resulting contents of the pool are what we expect.
	{
		pool.reconcile_block(&block)?;
		assert_eq!(pool.total_size(), 0);
	}

	// tx1 spends some outputs from the initial test tx.
	let tx1 = test_transaction(&keychain, vec![105, 106], vec![21, 22], &chain);
	assert!(pool
		.add_to_pool(test_source(), tx1.clone(), false, &header)
		.is_ok());
	let txs = pool.prepare_mineable_transactions()?;
	add_block(&chain, &txs, &keychain);
	let header = chain.head_header()?;
	let block = chain.get_block(&header.hash()).unwrap();

	// Now reconcile the transaction pool with the new block
	// and check the resulting contents of the pool are what we expect.
	{
		pool.reconcile_block(&block)?;
		assert_eq!(pool.total_size(), 0);
	}

	// tx2 spends some outputs from both tx1 and the initial test tx.
	let tx2 = test_transaction(&keychain, vec![107, 21], vec![31], &chain);

	assert!(pool
		.add_to_pool(test_source(), tx2.clone(), false, &header)
		.is_ok());

	{
		// Check we have a single initial tx in the pool.
		assert_eq!(pool.total_size(), 1);
	}

	// Test adding the exact same tx multiple times (same kernel signature).
	// This will fail for stem=false during tx aggregation due to duplicate
	// outputs and duplicate kernels.
	{
		assert!(pool
			.add_to_pool(test_source(), tx1.clone(), false, &header)
			.is_err());
	}

	// Test adding a duplicate tx with the same input and outputs.
	// Note: not the *same* tx, just same underlying inputs/outputs.
	{
		let tx2a = test_transaction(&keychain, vec![107, 21], vec![31], &chain);
		assert!(pool
			.add_to_pool(test_source(), tx2a, false, &header)
			.is_err());
	}

	// Test adding a tx attempting to spend a non-existent output.
	{
		// can't build this because index is not there for rp_hash
		// commenting out for now. TODO: figure out how to test this
		// but note, that the rp_hash could not be built so it would fail
		//let bad_tx = test_transaction(&keychain, vec![10_001], vec![9_900], &chain);
		//assert!(pool
		//	.add_to_pool(test_source(), bad_tx, false, &header)
		//	.is_err());
	}

	// Test adding a tx that would result in a duplicate output (conflicts with
	// output from tx2). For reasons of security all outputs in the UTXO set must
	// be unique. Otherwise spending one will almost certainly cause the other
	// to be immediately stolen via a "replay" tx.
	{
		let tx = test_transaction(&keychain, vec![107], vec![31], &chain);
		assert!(pool.add_to_pool(test_source(), tx, false, &header).is_err());
	}

	// Confirm the tx pool correctly identifies an invalid tx (already spent).
	{
		// can't build this because index is not there for rp_hash
		// commenting out for now. TODO: figure out how to test this
		// but note, that the rp_hash could not be built so it would fail
		//let bad_tx = test_transaction(&keychain, vec![10_001], vec![9_900], &chain);
		//let tx3 = test_transaction(&keychain, vec![105], vec![46], &chain);
		//assert!(pool
		//	.add_to_pool(test_source(), tx3, false, &header)
		//	.is_err());
		//assert_eq!(pool.total_size(), 3);
	}

	// Now add a couple of txs to the stempool (stem = true).
	let (tx1, tx2) = {
		let tx = test_transaction(&keychain, vec![108], vec![1], &chain);
		pool.add_to_pool(test_source(), tx.clone(), true, &header)
			.unwrap();
		let tx2 = test_transaction(&keychain, vec![109], vec![2], &chain);
		pool.add_to_pool(test_source(), tx2.clone(), true, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 1);
		assert_eq!(pool.stempool.size(), 2);
		(tx, tx2)
	};

	// Check we can take some entries from the stempool and "fluff" them into the
	// txpool. This also exercises multi-kernel txs.
	{
		let agg_tx = pool
			.stempool
			.all_transactions_aggregate(None)
			.unwrap()
			.unwrap();
		assert_eq!(agg_tx.kernels().len(), 2);
		pool.add_to_pool(test_source(), agg_tx, false, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 2);
		assert!(pool.stempool.is_empty());
	}

	// Adding a duplicate tx to the stempool will result in it being fluffed.
	// This handles the case of the stem path having a cycle in it.
	{
		let tx = test_transaction(&keychain, vec![110], vec![76], &chain);
		pool.add_to_pool(test_source(), tx.clone(), true, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 2);
		assert_eq!(pool.txpool.size(), 2);
		assert_eq!(pool.stempool.size(), 1);

		// Duplicate stem tx so fluff, adding it to txpool and removing it from stempool.
		pool.add_to_pool(test_source(), tx.clone(), true, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 3);
		assert_eq!(pool.txpool.size(), 3);
		assert!(pool.stempool.is_empty());
	}

	// Now check we can correctly deaggregate a multi-kernel tx based on current
	// contents of the txpool.
	// We will do this be adding a new tx to the pool
	// that is a superset of a tx already in the pool.
	{
		let tx4 = test_transaction(&keychain, vec![111], vec![77], &chain);

		// tx1 and tx2 are already in the txpool (in aggregated form)
		// tx4 is the "new" part of this aggregated tx that we care about
		let agg_tx = transaction::aggregate(&[tx1.clone(), tx2.clone(), tx4]).unwrap();

		let height = 4 + 1;
		agg_tx
			.validate(
				Weighting::AsTransaction,
				verifier_cache.clone(),
				height,
				None,
				None,
			)
			.unwrap();

		pool.add_to_pool(test_source(), agg_tx, false, &header)
			.unwrap();
		assert_eq!(pool.total_size(), 4);
		let entry = pool.txpool.entries.last().unwrap();
		assert_eq!(entry.tx.kernels().len(), 1);
		assert_eq!(entry.src, TxSource::Deaggregate);
	}

	// Check we cannot "double spend" an output spent in a previous block.
	// We use the initial coinbase output here for convenience.
	{
		// this no longer works because we can't build the rp_hash from an index that
		// doesn't exist.
		// TODO: determine how to test this.
		// but note, that the rp_hash could not be built so it would fail
		//let block_1 = chain.get_block(&header.hash()).unwrap();
		//let output = block_1.outputs()[0];
		//let index: u64 = chain.get_output_pos(&output.commitment()).unwrap() - 1;
		//let double_spend_tx =
		//	test_transaction_spending_coinbase(&keychain, &header, output, index, vec![249]);

		// check we cannot add a double spend to the stempool
		//assert!(pool
		//	.add_to_pool(test_source(), double_spend_tx.clone(), true, &header)
		//	.is_err());

		// check we cannot add a double spend to the txpool
		//assert!(pool
		//	.add_to_pool(test_source(), double_spend_tx.clone(), false, &header)
		//	.is_err());
	}

	// Cleanup db directory
	clean_output_dir(db_root.into());

	Ok(())
}
