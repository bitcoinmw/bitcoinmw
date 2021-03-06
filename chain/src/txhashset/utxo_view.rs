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

//! Lightweight readonly view into output MMR for convenience.

use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR};
use crate::core::core::{Block, BlockHeader, Inputs, Output, OutputIdentifier, Transaction};
use crate::core::global;
use crate::error::{Error, ErrorKind};
use crate::store::Batch;
use crate::types::CommitPos;
use crate::util::secp::pedersen::{Commitment, RangeProof};
use crate::util::RwLock;
use grin_core::core::verifier_cache::VerifierCache;
use grin_core::core::CommitWrapper;
use grin_store::pmmr::PMMRBackend;
use std::sync::Arc;

/// Readonly view of the UTXO set (based on output MMR).
pub struct UTXOView<'a> {
	header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
	output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
}

impl<'a> UTXOView<'a> {
	/// Build a new UTXO view.
	pub fn new(
		header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
		rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	) -> UTXOView<'a> {
		UTXOView {
			header_pmmr,
			output_pmmr,
			rproof_pmmr,
		}
	}

	/// Validate a block against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_block(
		&self,
		block: &Block,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		for output in block.outputs() {
			self.validate_output(output, batch)?;
		}
		self.validate_input_signatures(&block.inputs(), verifier, batch)?;
		self.validate_inputs(&block.inputs(), batch)
	}

	/// Validate a transaction against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_tx(
		&self,
		tx: &Transaction,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		for output in tx.outputs() {
			self.validate_output(output, batch)?;
		}
		self.validate_input_signatures(&tx.inputs(), verifier, batch)?;
		self.validate_inputs(&tx.inputs(), batch)
	}

	/// Validate the provided inputs.
	/// Returns a vec of output identifiers corresponding to outputs
	/// that would be spent by the provided inputs.
	pub fn validate_inputs(
		&self,
		inputs: &Inputs,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		let outputs_spent: Result<Vec<_>, Error> = inputs
			.0
			.iter()
			.map(|input| {
				self.validate_input(input.commitment(), batch)
					.and_then(|(out, pos)| Ok((out, pos)))
			})
			.collect();
		outputs_spent
	}

	/// This method checks the input signatures only
	pub fn validate_input_signatures(
		&self,
		inputs: &Inputs,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		let mut res: Vec<(OutputIdentifier, CommitPos)> = vec![];
		let inputs = {
			let mut accomplished_inputs_with_sig = vec![];
			for input in &inputs.0 {
				let validated = self.validate_input_with_sig(input.commitment(), batch)?;
				accomplished_inputs_with_sig.push((validated.0, validated.1, input.clone()));
				res.push((validated.0, validated.2));
			}
			accomplished_inputs_with_sig
		};

		//let filtered_accomplished_inputs_with_sig = inputs;
		let filtered_accomplished_inputs_with_sig = {
			let mut verifier = verifier.write();
			verifier.filter_input_with_sig_unverified(&inputs)
		};

		// Verify the unverified inputs signatures.
		// Signature verification need public key (i.e. that P' in this context), the P' has to be queried from chain UTXOs set.
		CommitWrapper::batch_sig_verify(&filtered_accomplished_inputs_with_sig)?;

		// Cache the successful verification results for the new inputs_with_sig.
		{
			let mut verifier = verifier.write();
			verifier.add_input_with_sig_verified(filtered_accomplished_inputs_with_sig);
		}

		Ok(res)
	}

	// Input is valid if it is spending an (unspent) output
	// that currently exists in the output MMR.
	// Note: We lookup by commitment. Caller must compare the full input as necessary.
	fn validate_input(
		&self,
		input: Commitment,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, CommitPos), Error> {
		let pos = batch.get_output_pos_height(&input)?;
		if let Some(pos) = pos {
			if let Some(out) = self.output_pmmr.get_data(pos.pos) {
				if out.commitment() == input {
					return Ok((out, pos));
				} else {
					error!("input mismatch: {:?}, {:?}, {:?}", out, pos, input);
					return Err(ErrorKind::Other(
						"input mismatch (output_pos index mismatch?)".into(),
					)
					.into());
				}
			}
		}
		Err(ErrorKind::AlreadySpent(input).into())
	}

	/// This function verifies the input signature
	fn validate_input_with_sig(
		&self,
		input: Commitment,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, Hash, CommitPos), Error> {
		let commit_pos = batch.get_output_pos_height(&input)?;
		if let Some(cp) = commit_pos {
			if let Some(out) = self.output_pmmr.get_data(cp.pos) {
				return if out.commitment() == input {
					if let Some(h) = self.rproof_pmmr.get_hash(cp.pos) {
						Ok((out, h, cp))
					} else {
						error!("rproof not exist: {:?}, {:?}, {:?}", out, cp, input);
						Err(ErrorKind::Other("rproof not exist".into()).into())
					}
				} else {
					error!("input mismatch: {:?}, {:?}, {:?}", out, cp, input);
					Err(
						ErrorKind::Other("input mismatch (output_pos index mismatch?)".into())
							.into(),
					)
				};
			}
		}
		Err(ErrorKind::AlreadySpent(input).into())
	}

	// Output is valid if it would not result in a duplicate commitment in the output MMR.
	fn validate_output(&self, output: &Output, batch: &Batch<'_>) -> Result<(), Error> {
		if let Ok(pos) = batch.get_output_pos(&output.commitment()) {
			if let Some(out_mmr) = self.output_pmmr.get_data(pos) {
				if out_mmr.commitment() == output.commitment() {
					return Err(ErrorKind::DuplicateCommitment(output.commitment()).into());
				}
			}
		}
		Ok(())
	}

	/// Retrieves an unspent output using its PMMR position
	pub fn get_unspent_output_at(&self, pos: u64) -> Result<Output, Error> {
		match self.output_pmmr.get_data(pos) {
			Some(output_id) => match self.rproof_pmmr.get_data(pos) {
				Some(rproof) => Ok(output_id.into_output(rproof)),
				None => Err(ErrorKind::RangeproofNotFound.into()),
			},
			None => Err(ErrorKind::OutputNotFound.into()),
		}
	}

	/// Get a list of spent utxos from the input list of positions
	pub fn get_mmr_check_list(&self, list: Vec<u64>) -> Result<Vec<u64>, Error> {
		let mut ret = vec![];
		for pos in list {
			match self.output_pmmr.get_data(pos) {
				None => ret.push(pos),
				_ => {}
			}
		}
		Ok(ret)
	}

	/// Verify we are not attempting to spend any coinbase outputs
	/// that have not sufficiently matured.
	pub fn verify_coinbase_maturity(
		&self,
		inputs: &Inputs,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		let inputs: Vec<_> = inputs.into();

		// Lookup the outputs being spent.
		let spent: Result<Vec<_>, _> = inputs
			.iter()
			.map(|x| self.validate_input(x.commitment(), batch))
			.collect();

		// Find the max pos of any coinbase being spent.
		let pos = spent?
			.iter()
			.filter_map(|(out, pos)| {
				if out.features.is_coinbase() {
					Some(pos.pos)
				} else {
					None
				}
			})
			.max();

		if let Some(pos) = pos {
			// If we have not yet reached 1440 blocks then
			// we can fail immediately as coinbase cannot be mature.
			if height < global::coinbase_maturity() {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}

			// Find the "cutoff" pos in the output MMR based on the
			// header from 1,000 blocks ago.
			let cutoff_height = height.saturating_sub(global::coinbase_maturity());
			let cutoff_header = self.get_header_by_height(cutoff_height, batch)?;
			let cutoff_pos = cutoff_header.output_mmr_size;

			// If any output pos exceed the cutoff_pos
			// we know they have not yet sufficiently matured.
			if pos > cutoff_pos {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}
		}

		Ok(())
	}

	/// Get the header hash for the specified pos from the underlying MMR backend.
	fn get_header_hash(&self, pos: u64) -> Option<Hash> {
		self.header_pmmr.get_data(pos).map(|x| x.hash())
	}

	/// Get the header at the specified height based on the current state of the extension.
	/// Derives the MMR pos from the height (insertion index) and retrieves the header hash.
	/// Looks the header up in the db by hash.
	pub fn get_header_by_height(
		&self,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<BlockHeader, Error> {
		let pos = pmmr::insertion_to_pmmr_index(height + 1);
		if let Some(hash) = self.get_header_hash(pos) {
			let header = batch.get_block_header(&hash)?;
			Ok(header)
		} else {
			Err(ErrorKind::Other("get header by height".to_string()).into())
		}
	}
}
