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

//! Implementation of the chain block acceptance (or refusal) pipeline.

use crate::core::consensus;
use crate::core::core::hash::Hashed;
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::Committed;
use crate::core::core::{
	block, Block, BlockHeader, BlockSums, HeaderVersion, OutputIdentifier, TransactionBody,
};
use crate::core::global;
use crate::core::pow;
use crate::error::{Error, ErrorKind};
use crate::store;
use crate::txhashset;
use crate::types::{CommitPos, Options, Tip};
use crate::util::RwLock;
use bitvec::prelude::*;
use bmw_utxo::utxo_data::UtxoData;
use grin_core::core::KernelFeatures;
use std::collections::HashMap;
use std::convert::TryInto;
use std::mem::replace;
use std::sync::{Arc, Weak};

/// Contextual information required to process a new block and either reject or
/// accept it.
pub struct BlockContext<'a> {
	/// The options
	pub opts: Options,
	/// The pow verifier to use when processing a block.
	pub pow_verifier: fn(&BlockHeader) -> Result<(), pow::Error>,
	/// The active txhashset (rewindable MMRs) to use for block processing.
	pub txhashset: &'a mut txhashset::TxHashSet,
	/// The active header MMR handle.
	pub header_pmmr: &'a mut txhashset::PMMRHandle<BlockHeader>,
	/// The active batch to use for block processing.
	pub batch: store::Batch<'a>,
	/// The verifier cache (caching verifier for rangeproofs and kernel signatures)
	pub verifier_cache: Arc<RwLock<dyn VerifierCache>>,
}

// If this block has greater total difficulty than treat as unknown in current context.
// If it matches current chain head (latest or previous hash) then we know about it.
// If it exists in the local db then we know about it.
fn check_known(header: &BlockHeader, head: &Tip, ctx: &BlockContext<'_>) -> Result<(), Error> {
	if header.total_difficulty() <= head.total_difficulty {
		check_known_head(header, head)?;
		check_known_store(header, head, ctx)?;
	}
	Ok(())
}

// Validate only the proof of work in a block header.
// Used to cheaply validate pow before checking if orphan or continuing block validation.
fn validate_pow_only(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	if ctx.opts.contains(Options::SKIP_POW) {
		// Some of our tests require this check to be skipped (we should revisit this).
		return Ok(());
	}
	if !header.pow.is_primary() && !header.pow.is_secondary() {
		return Err(ErrorKind::LowEdgebits.into());
	}
	if (ctx.pow_verifier)(header).is_err() {
		error!(
			"pipe: error validating header with cuckoo edge_bits {}",
			header.pow.edge_bits(),
		);
		return Err(ErrorKind::InvalidPow.into());
	}
	Ok(())
}

/// Runs the block processing pipeline, including validation and finding a
/// place for the new block in the chain.
/// Returns new head if chain head updated and the "fork point" rewound to when processing the new block.
pub fn process_block(
	b: &Block,
	ctx: &mut BlockContext<'_>,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
) -> Result<(Option<Tip>, BlockHeader), Error> {
	debug!(
		"pipe: process_block {} at {} [in/out/kern: {}/{}/{}] ({})",
		b.hash(),
		b.header.height,
		b.inputs().len(),
		b.outputs().len(),
		b.kernels().len(),
		b.inputs().version_str(),
	);

	// Read current chain head from db via the batch.
	// We use this for various operations later.
	let head = ctx.batch.head()?;

	// Check if we have already processed this block previously.
	check_known(&b.header, &head, ctx)?;

	// Quick pow validation. No point proceeding if this is invalid.
	// We want to do this before we add the block to the orphan pool so we
	// want to do this now and not later during header validation.
	validate_pow_only(&b.header, ctx)?;

	// Get previous header from the db.
	let prev = prev_header_store(&b.header, &mut ctx.batch)?;

	// Process the header for the block.
	// Note: We still want to process the full block if we have seen this header before
	// as we may have processed it "header first" and not yet processed the full block.
	process_block_header(&b.header, ctx)?;

	// Validate the block itself, make sure it is internally consistent.
	// Use the verifier_cache for verifying rangeproofs and kernel signatures.
	validate_block(b, ctx, utxo_data.clone())?;

	// Start a chain extension unit of work dependent on the success of the
	// internal validation and saving operations
	let header_pmmr = &mut ctx.header_pmmr;
	let txhashset = &mut ctx.txhashset;
	let batch = &mut ctx.batch;
	let verifier = ctx.verifier_cache.clone();
	let fork_point = txhashset::extending(
		header_pmmr,
		txhashset,
		batch,
		utxo_data.clone(),
		verifier,
		|ext, verifier, batch| {
			let fork_point =
				rewind_and_apply_fork(&prev, ext, verifier.clone(), batch, utxo_data.clone())?;

			// Check any coinbase being spent have matured sufficiently.
			// This needs to be done within the context of a potentially
			// rewound txhashset extension to reflect chain state prior
			// to applying the new block.
			verify_coinbase_maturity(b, ext, batch)?;

			// Validate the block against the UTXO set.
			validate_utxo(b, ext, verifier, batch)?;

			// Using block_sums (utxo_sum, kernel_sum) for the previous block from the db
			// we can verify_kernel_sums across the full UTXO sum and full kernel sum
			// accounting for inputs/outputs/kernels in this new block.
			// We know there are no double-spends etc. if this verifies successfully.
			verify_block_sums(b, batch, utxo_data.clone())?;

			// Validate the block against BTC Claim UTXOs.
			// Make sure no duplicates
			validate_btc_utxos(b, utxo_data.clone(), &fork_point, &head, batch)?;

			// Apply the block to the txhashset state.
			// Validate the txhashset roots and sizes against the block header.
			// Block is invalid if there are any discrepencies.
			apply_block_to_txhashset(b, ext, batch)?;

			// If applying this block does not increase the work on the chain then
			// we know we have not yet updated the chain to produce a new chain head.
			// We discard the "child" batch used in this extension (original ctx batch still active).
			// We discard any MMR modifications applied in this extension.
			let head = batch.head()?;
			if !has_more_work(&b.header, &head) {
				ext.extension.force_rollback();
			}

			Ok(fork_point)
		},
	)?;

	// Now that the block has been officially added, we update bitvecs with btc claims
	update_btc_utxo_bitvec(b, utxo_data, &fork_point, &head, batch)?;

	// Add the validated block to the db.
	// Note we do this in the outer batch, not the child batch from the extension
	// as we only commit the child batch if the extension increases total work.
	// We want to save the block to the db regardless.
	add_block(b, batch)?;

	// If we have no "tail" then set it now.
	if ctx.batch.tail().is_err() {
		update_body_tail(&b.header, &ctx.batch)?;
	}

	if has_more_work(&b.header, &head) {
		let head = Tip::from_header(&b.header);
		update_head(&head, &mut ctx.batch)?;
		Ok((Some(head), fork_point))
	} else {
		Ok((None, fork_point))
	}
}

/// Sync a chunk of block headers.
/// This is only used during header sync.
pub fn sync_block_headers(
	headers: &[BlockHeader],
	ctx: &mut BlockContext<'_>,
) -> Result<(), Error> {
	if headers.is_empty() {
		return Ok(());
	}
	let last_header = headers.last().expect("last header");

	// Check if we know about all these headers. If so we can accept them quickly.
	// If they *do not* increase total work on the sync chain we are done.
	// If they *do* increase total work then we should process them to update sync_head.
	let sync_head = {
		let hash = ctx.header_pmmr.head_hash()?;
		let header = ctx.batch.get_block_header(&hash)?;
		Tip::from_header(&header)
	};

	if let Ok(existing) = ctx.batch.get_block_header(&last_header.hash()) {
		if !has_more_work(&existing, &sync_head) {
			return Ok(());
		}
	}

	// Validate each header in the chunk and add to our db.
	// Note: This batch may be rolled back later if the MMR does not validate successfully.
	for header in headers {
		validate_header(header, ctx)?;
		add_block_header(header, &ctx.batch)?;
	}

	// Now apply this entire chunk of headers to the sync MMR (ctx is sync MMR specific).
	txhashset::header_extending(&mut ctx.header_pmmr, &mut ctx.batch, |ext, batch| {
		rewind_and_apply_header_fork(&last_header, ext, batch)?;
		Ok(())
	})
}

/// Process a block header. Update the header MMR and corresponding header_head if this header
/// increases the total work relative to header_head.
/// Note: In contrast to processing a full block we treat "already known" as success
/// to allow processing to continue (for header itself).
pub fn process_block_header(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	// If we have already processed the full block for this header then done.
	// Note: "already known" in this context is success so subsequent processing can continue.
	{
		let head = ctx.batch.head()?;
		if check_known(header, &head, ctx).is_err() {
			return Ok(());
		}
	}

	// Check this header is not an orphan, we must know about the previous header to continue.
	let prev_header = ctx.batch.get_previous_header(&header)?;

	// If we have not yet seen the full block then check if we have seen this header.
	// If it does not increase total_difficulty beyond our current header_head
	// then we can (re)accept this header and process the full block (or request it).
	// This header is on a fork and we should still accept it as the fork may eventually win.
	let header_head = ctx.batch.header_head()?;
	if let Ok(existing) = ctx.batch.get_block_header(&header.hash()) {
		if !has_more_work(&existing, &header_head) {
			return Ok(());
		}
	}

	// We want to validate this individual header before applying it to our header PMMR.
	validate_header(header, ctx)?;

	// Apply the header to the header PMMR, making sure we put the extension in the correct state
	// based on previous header first.
	txhashset::header_extending(&mut ctx.header_pmmr, &mut ctx.batch, |ext, batch| {
		rewind_and_apply_header_fork(&prev_header, ext, batch)?;
		ext.validate_root(header)?;
		ext.apply_header(header)?;
		if !has_more_work(&header, &header_head) {
			ext.force_rollback();
		}
		Ok(())
	})?;

	// Add this new block header to the db.
	add_block_header(header, &ctx.batch)?;

	if has_more_work(header, &header_head) {
		update_header_head(&Tip::from_header(header), &mut ctx.batch)?;
	}

	Ok(())
}

/// Quick check to reject recently handled blocks.
/// Checks against last_block_h and prev_block_h of the chain head.
fn check_known_head(header: &BlockHeader, head: &Tip) -> Result<(), Error> {
	let bh = header.hash();
	if bh == head.last_block_h || bh == head.prev_block_h {
		return Err(ErrorKind::Unfit("already known in head".to_string()).into());
	}
	Ok(())
}

// Check if this block is in the store already.
fn check_known_store(
	header: &BlockHeader,
	head: &Tip,
	ctx: &BlockContext<'_>,
) -> Result<(), Error> {
	match ctx.batch.block_exists(&header.hash()) {
		Ok(true) => {
			if header.height < head.height.saturating_sub(50) {
				// TODO - we flag this as an "abusive peer" but only in the case
				// where we have the full block in our store.
				// So this is not a particularly exhaustive check.
				Err(ErrorKind::OldBlock.into())
			} else {
				Err(ErrorKind::Unfit("already known in store".to_string()).into())
			}
		}
		Ok(false) => {
			// Not yet processed this block, we can proceed.
			Ok(())
		}
		Err(e) => Err(ErrorKind::StoreErr(e, "pipe get this block".to_owned()).into()),
	}
}

// Find the previous header from the store.
// Return an Orphan error if we cannot find the previous header.
fn prev_header_store(
	header: &BlockHeader,
	batch: &mut store::Batch<'_>,
) -> Result<BlockHeader, Error> {
	let prev = batch.get_previous_header(&header)?;
	Ok(prev)
}

/// First level of block validation that only needs to act on the block header
/// to make it as cheap as possible. The different validations are also
/// arranged by order of cost to have as little DoS surface as possible.
fn validate_header(header: &BlockHeader, ctx: &mut BlockContext<'_>) -> Result<(), Error> {
	// First I/O cost, delayed as late as possible.
	let prev = prev_header_store(header, &mut ctx.batch)?;

	// This header height must increase the height from the previous header by exactly 1.
	if header.height != prev.height + 1 {
		return Err(ErrorKind::InvalidBlockHeight.into());
	}

	// This header must have a valid header version for its height.
	if !consensus::valid_header_version(header.height, header.version) {
		return Err(ErrorKind::InvalidBlockVersion(header.version).into());
	}

	if header.timestamp <= prev.timestamp {
		// prevent time warp attacks and some timestamp manipulations by forcing strict
		// time progression
		return Err(ErrorKind::InvalidBlockTime.into());
	}

	// We can determine output and kernel counts for this block based on mmr sizes from previous header.
	// Assume 0 inputs and estimate a lower bound on the full block weight.
	let num_outputs = header
		.output_mmr_count()
		.saturating_sub(prev.output_mmr_count());
	let num_kernels = header
		.kernel_mmr_count()
		.saturating_sub(prev.kernel_mmr_count());

	// Each block must contain at least 1 kernel and 1 output for the block reward.
	if num_outputs == 0 || num_kernels == 0 {
		return Err(ErrorKind::InvalidMMRSize.into());
	}

	// Block header is invalid (and block is invalid) if this lower bound is too heavy for a full block.
	let weight = TransactionBody::weight_by_iok(0, num_outputs, num_kernels);
	if weight > global::max_block_weight() {
		return Err(ErrorKind::Block(block::Error::TooHeavy).into());
	}

	// verify the proof of work and related parameters
	// at this point we have a previous block header
	// we know the height increased by one
	// so now we can check the total_difficulty increase is also valid
	// check the pow hash shows a difficulty at least as large
	// as the target difficulty
	if !ctx.opts.contains(Options::SKIP_POW) {
		// Quick check of this header in isolation. No point proceeding if this fails.
		// We can do this without needing to iterate over previous headers.
		validate_pow_only(header, ctx)?;

		if header.total_difficulty() <= prev.total_difficulty() {
			return Err(ErrorKind::DifficultyTooLow.into());
		}

		let target_difficulty = header.total_difficulty() - prev.total_difficulty();

		if header.pow.to_difficulty(header.height) < target_difficulty {
			return Err(ErrorKind::DifficultyTooLow.into());
		}

		// explicit check to ensure total_difficulty has increased by exactly
		// the _network_ difficulty of the previous block
		// (during testnet1 we use _block_ difficulty here)
		let child_batch = ctx.batch.child()?;
		let diff_iter = store::DifficultyIter::from_batch(prev.hash(), child_batch);
		let next_header_info = consensus::next_difficulty(header.height, diff_iter);
		if target_difficulty != next_header_info.difficulty {
			info!(
				"validate_header: header target difficulty {} != {}",
				target_difficulty.to_num(),
				next_header_info.difficulty.to_num()
			);
			return Err(ErrorKind::WrongTotalDifficulty.into());
		}
		// check the secondary PoW scaling factor if applicable
		if header.version < HeaderVersion(5)
			&& header.pow.secondary_scaling != next_header_info.secondary_scaling
		{
			info!(
				"validate_header: header secondary scaling {} != {}",
				header.pow.secondary_scaling, next_header_info.secondary_scaling
			);
			return Err(ErrorKind::InvalidScaling.into());
		}
	}

	Ok(())
}

fn validate_block(
	block: &Block,
	ctx: &mut BlockContext<'_>,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
) -> Result<(), Error> {
	let prev = ctx.batch.get_previous_header(&block.header)?;
	block
		.validate(
			&prev.total_kernel_offset,
			ctx.verifier_cache.clone(),
			utxo_data,
		)
		.map_err(ErrorKind::InvalidBlockProof)?;
	Ok(())
}

/// Verify the block is not spending coinbase outputs before they have sufficiently matured.
fn verify_coinbase_maturity(
	block: &Block,
	ext: &txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	let extension = &ext.extension;
	let header_extension = &ext.header_extension;
	extension
		.utxo_view(header_extension)
		.verify_coinbase_maturity(&block.inputs(), block.header.height, batch)
}

/// Verify kernel sums across the full utxo and kernel sets based on block_sums
/// of previous block accounting for the inputs|outputs|kernels of the new block.
/// Saves the new block_sums to the db via the current batch if successful.
fn verify_block_sums(
	b: &Block,
	batch: &store::Batch<'_>,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
) -> Result<(), Error> {
	// Retrieve the block_sums for the previous block.
	let block_sums = batch.get_block_sums(&b.header.prev_hash)?;

	// Overage is based purely on the new block.
	// Previous block_sums have taken all previous overage into account.
	let overage = b.overage(utxo_data);

	// Offset on the other hand is the total kernel offset from the new block.
	let offset = b.header.total_kernel_offset();

	// Verify the kernel sums for the block_sums with the new block applied.
	let (utxo_sum, kernel_sum) =
		(block_sums, b as &dyn Committed).verify_kernel_sums(overage, offset)?;

	batch.save_block_sums(
		&b.hash(),
		BlockSums {
			utxo_sum,
			kernel_sum,
		},
	)?;

	Ok(())
}

/// Fully validate the block by applying it to the txhashset extension.
/// Check both the txhashset roots and sizes are correct after applying the block.
fn apply_block_to_txhashset(
	block: &Block,
	ext: &mut txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	ext.extension
		.apply_block(block, ext.header_extension, batch)?;
	ext.extension.validate_roots(&block.header)?;
	ext.extension.validate_sizes(&block.header)?;
	Ok(())
}

/// Officially adds the block to our chain (possibly on a losing fork).
/// Header must be added separately (assume this has been done previously).
fn add_block(b: &Block, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch.save_block(b)?;
	Ok(())
}

/// Update the block chain tail so we can know the exact tail of full blocks in this node
fn update_body_tail(bh: &BlockHeader, batch: &store::Batch<'_>) -> Result<(), Error> {
	let tip = Tip::from_header(bh);
	batch
		.save_body_tail(&tip)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save body tail".to_owned()))?;
	debug!("body tail {} @ {}", bh.hash(), bh.height);
	Ok(())
}

/// Officially adds the block header to our header chain.
fn add_block_header(bh: &BlockHeader, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_block_header(bh)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save header".to_owned()))?;
	Ok(())
}

fn update_header_head(head: &Tip, batch: &mut store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_header_head(&head)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save header head".to_owned()))?;

	debug!(
		"header head updated to {} at {}",
		head.last_block_h, head.height
	);

	Ok(())
}

fn update_head(head: &Tip, batch: &mut store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_body_head(&head)
		.map_err(|e| ErrorKind::StoreErr(e, "pipe save body".to_owned()))?;

	debug!("head updated to {} at {}", head.last_block_h, head.height);

	Ok(())
}

/// Whether the provided block totals more work than the chain tip
fn has_more_work(header: &BlockHeader, head: &Tip) -> bool {
	header.total_difficulty() > head.total_difficulty
}

/// Rewind the header chain and reapply headers on a fork.
pub fn rewind_and_apply_header_fork(
	header: &BlockHeader,
	ext: &mut txhashset::HeaderExtension<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	let mut fork_hashes = vec![];
	let mut current = header.clone();
	while current.height > 0 && ext.is_on_current_chain(&current, batch).is_err() {
		fork_hashes.push(current.hash());
		current = batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	let forked_header = current;

	// Rewind the txhashset state back to the block where we forked from the most work chain.
	ext.rewind(&forked_header)?;

	// Re-apply all headers on this fork.
	for h in fork_hashes {
		let header = batch
			.get_block_header(&h)
			.map_err(|e| ErrorKind::StoreErr(e, "getting forked headers".to_string()))?;
		ext.validate_root(&header)?;
		ext.apply_header(&header)?;
	}

	Ok(())
}

/// Utility function to handle forks. From the forked block, jump backward
/// to find to fork point. Rewind the txhashset to the fork point and apply all
/// necessary blocks prior to the one being processed to set the txhashset in
/// the expected state.
/// Returns the "fork point" that we rewound to.
pub fn rewind_and_apply_fork(
	header: &BlockHeader,
	ext: &mut txhashset::ExtensionPair<'_>,
	verifier: Arc<RwLock<dyn VerifierCache>>,
	batch: &store::Batch<'_>,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
) -> Result<BlockHeader, Error> {
	let extension = &mut ext.extension;
	let header_extension = &mut ext.header_extension;

	// Prepare the header MMR.
	rewind_and_apply_header_fork(header, header_extension, batch)?;

	// Rewind the txhashset extension back to common ancestor based on header MMR.
	let mut current = batch.head_header()?;
	while current.height > 0
		&& header_extension
			.is_on_current_chain(&current, batch)
			.is_err()
	{
		current = batch.get_previous_header(&current)?;
	}
	let fork_point = current;
	extension.rewind(&fork_point, batch)?;

	// Then apply all full blocks since this common ancestor
	// to put txhashet extension in a state to accept the new block.
	let mut fork_hashes = vec![];
	let mut current = header.clone();
	while current.height > fork_point.height {
		fork_hashes.push(current.hash());
		current = batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	for h in fork_hashes {
		let fb = batch
			.get_block(&h)
			.map_err(|e| ErrorKind::StoreErr(e, "getting forked blocks".to_string()))?;

		// Re-verify coinbase maturity along this fork.
		verify_coinbase_maturity(&fb, ext, batch)?;
		// Validate the block against the UTXO set.
		validate_utxo(&fb, ext, verifier.clone(), batch)?;
		// Re-verify block_sums to set the block_sums up on this fork correctly.
		verify_block_sums(&fb, batch, utxo_data.clone())?;
		// Re-apply the blocks.
		apply_block_to_txhashset(&fb, ext, batch)?;
	}

	Ok(fork_point)
}

/// rewind a bitvec to the fork point. Update any BTCClaims that are affected.
fn rewind_btc_bitvec(
	mut bitvec: BitVec,
	fork_point: &BlockHeader,
	head: &Tip,
	_bheader: &BlockHeader,
	batch: &store::Batch<'_>,
) -> Result<BitVec, Error> {
	// get current head
	let mut current = batch.get_block(&head.last_block_h)?.header;
	// create a vec of the fork_hashes between current head and fork_point
	let mut fork_hashes = vec![];
	while current.height > fork_point.height {
		fork_hashes.push(current.hash());
		current = batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	// iterate through each hash
	for h in fork_hashes {
		let fb = batch
			.get_block(&h)
			.map_err(|e| ErrorKind::StoreErr(e, "getting forked blocks".to_string()))?;
		for k in fb.kernels() {
			match k.features {
				KernelFeatures::BTCClaim { index, .. } => {
					// set any BTCClaims to false because they were on another chain
					bitvec.set(index.try_into()?, false);
				}
				_ => {}
			}
		}
	}

	Ok(bitvec)
}

/// Apply the fork blocks to the bitvec starting at the fork_point.
fn apply_fork_btc_bitvec(
	mut bitvec: BitVec,
	fork_point: &BlockHeader,
	_head: &Tip,
	bheader: &BlockHeader,
	batch: &store::Batch<'_>,
) -> Result<BitVec, Error> {
	// get the current header
	let mut current = bheader.clone();
	// get all fork hashes of the blocks from fork_point to this block
	let mut fork_hashes = vec![];

	// don't look at current header, rewind by one
	current = batch.get_previous_header(&current)?;

	while current.height > fork_point.height {
		fork_hashes.push(current.hash());
		current = batch.get_previous_header(&current)?;
	}
	// reverse the vec
	fork_hashes.reverse();

	// iterate through the fork_hashes and check each BTCClaim, update bitvec
	for h in fork_hashes {
		let fb = batch
			.get_block(&h)
			.map_err(|e| ErrorKind::StoreErr(e, "getting forked blocks".to_string()))?;
		for k in fb.kernels() {
			match k.features {
				KernelFeatures::BTCClaim { index, .. } => {
					bitvec.set(index.try_into()?, true);
				}
				_ => {}
			}
		}
	}

	// return updated bitvec
	Ok(bitvec)
}

/// Rewind the block to the fork point and apply the new blocks of the fork
/// to the bitvec so an accurate answer as to whether or not the BTClaim has
/// already been made on this chain.
fn rewind_and_apply_fork_btc_bitvec(
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
	fork_point: &BlockHeader,
	head: &Tip,
	bheader: &BlockHeader,
	batch: &store::Batch<'_>,
) -> Result<BitVec, Error> {
	if utxo_data.is_none() {
		// if no utxo_data (like in tests), we return an empty bitvec.
		return Ok(BitVec::new());
	}

	// safely get the utxo_data struct.
	let utxo_data = utxo_data
		.as_ref()
		.ok_or(Error::from(ErrorKind::NoneError))?
		.upgrade()
		.ok_or(Error::from(ErrorKind::NoneError))?;
	let utxo_data = utxo_data.write();
	let bitvec = &*utxo_data.claims_bitmap.lock()?;

	// if this is the next header on the chain, return the bitvec as no adjustments needed
	if has_more_work(bheader, &head) {
		if bheader.prev_hash == head.hash() {
			return Ok(bitvec.clone());
		}
	}

	// rewind the bitvec to fork point
	let bitvec = rewind_btc_bitvec(bitvec.clone(), fork_point, head, bheader, batch)?;

	// apply the fork headers to the bitvec
	let bitvec = apply_fork_btc_bitvec(bitvec, fork_point, head, bheader, batch)?;
	Ok(bitvec)
}

/// Update the bitvec if this is a new tip of the chain
fn update_btc_utxo_bitvec(
	b: &Block,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
	fork_point: &BlockHeader,
	head: &Tip,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	if utxo_data.is_none() {
		return Ok(());
	}

	// We only update the bitvec if there's more work here.
	if has_more_work(&b.header, &head) {
		// get the appropriate bitvec
		let bitslice = &mut *rewind_and_apply_fork_btc_bitvec(
			utxo_data.clone(),
			fork_point,
			head,
			&b.header,
			batch,
		)?;

		// iterate through kernels in the block and update the bitvec with any BTCClaims
		for kernel in &b.body.kernels {
			match kernel.features {
				KernelFeatures::BTCClaim { index, .. } => {
					// if we have an index in our bitmap update it.
					bitslice.set(index.try_into()?, true);
				}
				_ => {}
			}
		}

		// safely get the utxo_data struct.
		let utxo_data = utxo_data
			.as_ref()
			.ok_or(Error::from(ErrorKind::NoneError))?
			.upgrade()
			.ok_or(Error::from(ErrorKind::NoneError))?;
		let utxo_data = utxo_data.write();

		// get the claims bitmap
		let cmap = &mut *utxo_data.claims_bitmap.lock()?;
		// replace in memory the bitmap
		let _ = replace(cmap, (*bitslice).to_bitvec());
	}

	Ok(())
}

/// Validate the btc utxos in the claims. Ensure no duplicates.
fn validate_btc_utxos(
	b: &Block,
	utxo_data: Option<Weak<RwLock<UtxoData>>>,
	fork_point: &BlockHeader,
	head: &Tip,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	// if we have no utxo_data (as in some tests), we must continue processing.
	if utxo_data.is_none() {
		return Ok(());
	}

	// get the correct bitslice which is adjusted for forks
	let bitslice = &mut *rewind_and_apply_fork_btc_bitvec(
		utxo_data.clone(),
		fork_point,
		head,
		&b.header,
		batch,
	)?;

	// safely get the utxo_data struct.
	let utxo_data = utxo_data
		.as_ref()
		.ok_or(Error::from(ErrorKind::NoneError))?
		.upgrade()
		.ok_or(Error::from(ErrorKind::NoneError))?;
	let utxo_data = utxo_data.read();

	// create an index map to ensure this block does not have two of the same Claims in it
	let mut index_map: HashMap<u32, bool> = HashMap::new();

	// iterate through each kernel in this block.
	for kernel in &b.body.kernels {
		match kernel.features {
			KernelFeatures::BTCClaim { index, .. } => {
				// only check BTCClaims
				let index_usize: usize = index.try_into()?;
				let index_u32: u32 = index.try_into()?;

				// if this index is greater than the size of the bitmap, return error
				if index_usize >= (*bitslice).len() {
					return Err(ErrorKind::Unfit(format!("Invalid index for BTCClaim")).into());
				}

				let found = (*bitslice).get(index_usize);
				// If nothing is found there's something wrong, return error.
				if found.is_none() {
					return Err(ErrorKind::Unfit(format!("Invalid index for BTCClaim")).into());
				}

				// if it is found and it's true, that means it's already claimed. Return error.
				if *found.unwrap() {
					return Err(ErrorKind::Unfit(format!(
						"BTC address [{:?}] has already been claimed",
						utxo_data.get_address(index_u32)
					))
					.into());
				}

				// if it's found in the index_map, this block already has this index. Return error.
				if index_map.get(&index_u32).is_some() {
					return Err(ErrorKind::Unfit(format!(
						"BTC address [{:?}] found twice in this block",
						utxo_data.get_address(index_u32)
					))
					.into());
				}

				// Insert the index into the map to detect later duplicates in the block
				index_map.insert(index, true);
			}
			_ => {}
		}
	}

	Ok(())
}

/// Validate block inputs and outputs against utxo.
/// Every input must spend an unspent output.
/// No duplicate outputs created.
fn validate_utxo(
	block: &Block,
	ext: &mut txhashset::ExtensionPair<'_>,
	verifier: Arc<RwLock<dyn VerifierCache>>,
	batch: &store::Batch<'_>,
) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
	let extension = &ext.extension;
	let header_extension = &ext.header_extension;
	extension
		.utxo_view(header_extension)
		.validate_block(block, verifier, batch)
}
