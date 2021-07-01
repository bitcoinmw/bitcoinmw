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

use super::utils::{get_output, get_output_v2, w};
use crate::chain;
use crate::core::core::hash::Hashed;
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::util;
use crate::util::secp::pedersen::Commitment;
use crate::util::RwLock;
use crate::web::*;
use bmw_utxo::utxo_data::UtxoData;
use failure::ResultExt;
use grin_util::ToHex;
use hyper::{Body, Request, StatusCode};
use std::convert::TryInto;
use std::sync::Weak;

/// Chain handler. Get the head details.
/// GET /v1/chain
pub struct ChainHandler {
	pub chain: Weak<chain::Chain>,
	pub utxo_data: Weak<RwLock<UtxoData>>,
}

impl ChainHandler {
	pub fn get_tip(&self) -> Result<Tip, Error> {
		let head = w(&self.chain)?
			.head()
			.map_err(|e| ErrorKind::Internal(format!("can't get head: {}", e)))?;
		Ok(Tip::from_tip(head))
	}

	pub fn get_btc_address_status(&self, address: String) -> Result<AddressStatus, Error> {
		// get our utxo_data
		let wval = w(&self.utxo_data)?;
		// obtain read lock
		let wval = wval.read();
		// get the btc_address if it exists
		let val = (*wval).get_index(address.clone());
		let valid = val.is_ok();
		let mut unclaimed = false; // unclaimed will be false if it's not valid
		let mut sats = 0;
		let mut index = 0;
		if val.is_ok() {
			// get sats for this address
			sats = (*wval).get_sats_by_address(address).unwrap();
			// get index
			index = val.unwrap();
			// check to see whether this is already claimed
			let bitvec = wval.claims_bitmap.lock().unwrap();
			unclaimed = !*bitvec.get(index.try_into().unwrap_or(0)).unwrap();
		}

		// return appropriate structure
		Ok(AddressStatus {
			valid,
			unclaimed,
			sats,
			index,
		})
	}

	pub fn scan(
		&self,
		client_headers: Vec<(String, u64, u64)>,
		max_outputs: u64,
		offset_mmr_index: u64,
		mmr_check: Vec<u64>,
		is_syncing: bool,
	) -> Result<ScanResponse, Error> {
		if is_syncing {
			return Ok(ScanResponse {
				is_syncing: true,
				last_pmmr_index: 0,
				headers: vec![],
				outputs: vec![],
				mmr_spent: vec![],
			});
		}

		let chain = w(&self.chain)?;
		let mut highest_valid_header = 0;

		for header in client_headers {
			let internal_hash = chain.get_header_hash_by_height(header.1)?.to_hex();
			if internal_hash == header.0 {
				// this header is valid
				if header.1 > highest_valid_header {
					highest_valid_header = header.1;
				}
			}
		}

		// get the last valid mmr index
		let last_valid_header = chain.get_header_by_height(highest_valid_header)?;
		let mut start_index = last_valid_header.output_mmr_size + 1;
		if start_index < offset_mmr_index {
			start_index = offset_mmr_index;
		}

		let outputs = chain
			.unspent_outputs_by_pmmr_index(start_index, max_outputs, None)?
			.2;

		let outputs = {
			let mut ret = vec![];
			for output in outputs {
				let commit_pos = chain.get_unspent(output.identifier.commit)?;
				match commit_pos {
					Some(commit_pos) => {
						let pos = commit_pos.1.pos;
						let height = commit_pos.1.height;
						ret.push((pos, height, output));
					}
					None => {
						return Err(ErrorKind::Internal("output not found".to_string()).into());
					}
				}
			}

			ret
		};

		let head = chain.head_header()?;
		let last_pmmr_index = head.output_mmr_size;
		let mut headers = vec![];
		let mut height = head.height;
		let mut count = 0;
		loop {
			let hash = chain.get_header_hash_by_height(height)?;
			let output_mmr_index = chain.get_header_by_height(height)?.output_mmr_size;
			headers.push((hash.to_hex(), height, output_mmr_index));

			// maximum of 10 headers
			if height <= 100 || count >= 10 {
				break;
			}
			count += 1;
			height -= 100;
		}

		// check spent mmrs
		let mmr_spent = chain.get_mmr_check_list(mmr_check)?;

		Ok(ScanResponse {
			is_syncing: false,
			last_pmmr_index,
			headers,
			outputs,
			mmr_spent,
		})
	}
}

impl Handler for ChainHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
		result_to_response(self.get_tip())
	}
}

/// Chain validation handler.
/// GET /v1/chain/validate
pub struct ChainValidationHandler {
	pub chain: Weak<chain::Chain>,
}

impl ChainValidationHandler {
	pub fn validate_chain(&self) -> Result<(), Error> {
		w(&self.chain)?
			.validate(true)
			.map_err(|_| ErrorKind::Internal("chain error".to_owned()).into())
	}
}

impl Handler for ChainValidationHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
		match w_fut!(&self.chain).validate(true) {
			Ok(_) => response(StatusCode::OK, "{}"),
			Err(e) => response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("validate failed: {}", e),
			),
		}
	}
}

/// Chain compaction handler. Trigger a compaction of the chain state to regain
/// storage space.
/// POST /v1/chain/compact
pub struct ChainCompactHandler {
	pub chain: Weak<chain::Chain>,
}

impl ChainCompactHandler {
	pub fn compact_chain(&self) -> Result<(), Error> {
		w(&self.chain)?
			.compact()
			.map_err(|_| ErrorKind::Internal("chain error".to_owned()).into())
	}
}

impl Handler for ChainCompactHandler {
	fn post(&self, _req: Request<Body>) -> ResponseFuture {
		match w_fut!(&self.chain).compact() {
			Ok(_) => response(StatusCode::OK, "{}"),
			Err(e) => response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("compact failed: {}", e),
			),
		}
	}
}

// Supports retrieval of multiple outputs in a single request -
// GET /v1/chain/outputs/byids?id=xxx,yyy,zzz
// GET /v1/chain/outputs/byids?id=xxx&id=yyy&id=zzz
// GET /v1/chain/outputs/byheight?start_height=101&end_height=200
pub struct OutputHandler {
	pub chain: Weak<chain::Chain>,
}

impl OutputHandler {
	pub fn get_outputs_v2(
		&self,
		commits: Option<Vec<String>>,
		start_height: Option<u64>,
		end_height: Option<u64>,
		include_proof: Option<bool>,
		include_merkle_proof: Option<bool>,
	) -> Result<Vec<OutputPrintable>, Error> {
		let mut outputs: Vec<OutputPrintable> = vec![];
		if let Some(commits) = commits {
			// First check the commits length
			for commit in &commits {
				if commit.len() != 66 {
					return Err(ErrorKind::RequestError(format!(
						"invalid commit length for {}",
						commit
					))
					.into());
				}
			}
			for commit in commits {
				match get_output_v2(
					&self.chain,
					&commit,
					include_proof.unwrap_or(false),
					include_merkle_proof.unwrap_or(false),
				) {
					Ok(Some((output, _))) => outputs.push(output),
					Ok(None) => {
						// Ignore outputs that are not found
					}
					Err(e) => {
						error!(
							"Failure to get output for commitment {} with error {}",
							commit, e
						);
						return Err(e);
					}
				};
			}
		}
		// cannot chain to let Some() for now  see https://github.com/rust-lang/rust/issues/53667
		if let Some(start_height) = start_height {
			if let Some(end_height) = end_height {
				let block_output_batch = self.outputs_block_batch_v2(
					start_height,
					end_height,
					include_proof.unwrap_or(false),
					include_merkle_proof.unwrap_or(false),
				)?;
				outputs = [&outputs[..], &block_output_batch[..]].concat();
			}
		}
		Ok(outputs)
	}

	// allows traversal of utxo set
	pub fn get_unspent_outputs(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		mut max: u64,
		include_proof: Option<bool>,
	) -> Result<OutputListing, Error> {
		//set a limit here
		if max > 10_000 {
			max = 10_000;
		}
		let chain = w(&self.chain)?;
		let outputs = chain
			.unspent_outputs_by_pmmr_index(start_index, max, end_index)
			.context(ErrorKind::NotFound)?;
		let out = OutputListing {
			last_retrieved_index: outputs.0,
			highest_index: outputs.1,
			outputs: outputs
				.2
				.iter()
				.map(|x| {
					OutputPrintable::from_output(
						x,
						&chain,
						None,
						include_proof.unwrap_or(false),
						false,
					)
				})
				.collect::<Result<Vec<_>, _>>()
				.context(ErrorKind::Internal("chain error".to_owned()))?,
		};
		Ok(out)
	}

	fn outputs_by_ids(&self, req: &Request<Body>) -> Result<Vec<Output>, Error> {
		let mut commitments: Vec<String> = vec![];

		let query = must_get_query!(req);
		let params = QueryParams::from(query);
		params.process_multival_param("id", |id| commitments.push(id.to_owned()));

		let mut outputs: Vec<Output> = vec![];
		for x in commitments {
			match get_output(&self.chain, &x) {
				Ok(Some((output, _))) => outputs.push(output),
				Ok(None) => {
					// Ignore outputs that are not found
				}
				Err(e) => {
					error!(
						"Failure to get output for commitment {} with error {}",
						x, e
					);
					return Err(e);
				}
			};
		}
		Ok(outputs)
	}

	fn outputs_at_height(
		&self,
		block_height: u64,
		commitments: Vec<Commitment>,
		include_proof: bool,
	) -> Result<BlockOutputs, Error> {
		let header = w(&self.chain)?
			.get_header_by_height(block_height)
			.map_err(|_| ErrorKind::NotFound)?;

		// TODO - possible to compact away blocks we care about
		// in the period between accepting the block and refreshing the wallet
		let chain = w(&self.chain)?;
		let block = chain
			.get_block(&header.hash())
			.map_err(|_| ErrorKind::NotFound)?;
		let outputs = block
			.outputs()
			.iter()
			.filter(|output| commitments.is_empty() || commitments.contains(&output.commitment()))
			.map(|output| {
				OutputPrintable::from_output(output, &chain, Some(&header), include_proof, true)
			})
			.collect::<Result<Vec<_>, _>>()
			.context(ErrorKind::Internal("cain error".to_owned()))?;

		Ok(BlockOutputs {
			header: BlockHeaderInfo::from_header(&header),
			outputs: outputs,
		})
	}

	fn outputs_at_height_v2(
		&self,
		block_height: u64,
		commitments: Vec<Commitment>,
		include_rproof: bool,
		include_merkle_proof: bool,
	) -> Result<Vec<OutputPrintable>, Error> {
		let header = w(&self.chain)?
			.get_header_by_height(block_height)
			.map_err(|_| ErrorKind::NotFound)?;

		// TODO - possible to compact away blocks we care about
		// in the period between accepting the block and refreshing the wallet
		let chain = w(&self.chain)?;
		let block = chain
			.get_block(&header.hash())
			.map_err(|_| ErrorKind::NotFound)?;
		let outputs = block
			.outputs()
			.iter()
			.filter(|output| commitments.is_empty() || commitments.contains(&output.commitment()))
			.map(|output| {
				OutputPrintable::from_output(
					output,
					&chain,
					Some(&header),
					include_rproof,
					include_merkle_proof,
				)
			})
			.collect::<Result<Vec<_>, _>>()
			.context(ErrorKind::Internal("cain error".to_owned()))?;

		Ok(outputs)
	}

	// returns outputs for a specified range of blocks
	fn outputs_block_batch(&self, req: &Request<Body>) -> Result<Vec<BlockOutputs>, Error> {
		let mut commitments: Vec<Commitment> = vec![];

		let query = must_get_query!(req);
		let params = QueryParams::from(query);
		params.process_multival_param("id", |id| {
			if let Ok(x) = util::from_hex(id) {
				commitments.push(Commitment::from_vec(x));
			}
		});
		let start_height = parse_param!(params, "start_height", 1);
		let end_height = parse_param!(params, "end_height", 1);
		let include_rp = params.get("include_rp").is_some();

		debug!(
			"outputs_block_batch: {}-{}, {:?}, {:?}",
			start_height, end_height, commitments, include_rp,
		);

		let mut return_vec = vec![];
		for i in (start_height..=end_height).rev() {
			if let Ok(res) = self.outputs_at_height(i, commitments.clone(), include_rp) {
				if !res.outputs.is_empty() {
					return_vec.push(res);
				}
			}
		}

		Ok(return_vec)
	}

	// returns outputs for a specified range of blocks
	fn outputs_block_batch_v2(
		&self,
		start_height: u64,
		end_height: u64,
		include_rproof: bool,
		include_merkle_proof: bool,
	) -> Result<Vec<OutputPrintable>, Error> {
		let commitments: Vec<Commitment> = vec![];

		debug!(
			"outputs_block_batch: {}-{}, {}, {}",
			start_height, end_height, include_rproof, include_merkle_proof,
		);

		let mut return_vec: Vec<OutputPrintable> = vec![];
		for i in (start_height..=end_height).rev() {
			if let Ok(res) = self.outputs_at_height_v2(
				i,
				commitments.clone(),
				include_rproof,
				include_merkle_proof,
			) {
				if !res.is_empty() {
					return_vec = [&return_vec[..], &res[..]].concat();
				}
			}
		}

		Ok(return_vec)
	}
}

impl Handler for OutputHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		match right_path_element!(req) {
			"byids" => result_to_response(self.outputs_by_ids(&req)),
			"byheight" => result_to_response(self.outputs_block_batch(&req)),
			_ => response(StatusCode::BAD_REQUEST, ""),
		}
	}
}

/// Kernel handler, search for a kernel by excess commitment
/// GET /v1/chain/kernels/XXX?min_height=YYY&max_height=ZZZ
/// The `min_height` and `max_height` parameters are optional
pub struct KernelHandler {
	pub chain: Weak<chain::Chain>,
}

impl KernelHandler {
	fn get_kernel(&self, req: Request<Body>) -> Result<Option<LocatedTxKernel>, Error> {
		let excess = req
			.uri()
			.path()
			.trim_end_matches('/')
			.rsplit('/')
			.next()
			.ok_or_else(|| ErrorKind::RequestError("missing excess".into()))?;
		let excess = util::from_hex(excess)
			.map_err(|_| ErrorKind::RequestError("invalid excess hex".into()))?;
		if excess.len() != 33 {
			return Err(ErrorKind::RequestError("invalid excess length".into()).into());
		}
		let excess = Commitment::from_vec(excess);

		let chain = w(&self.chain)?;

		let mut min_height: Option<u64> = None;
		let mut max_height: Option<u64> = None;

		// Check query parameters for minimum and maximum search height
		if let Some(q) = req.uri().query() {
			let params = QueryParams::from(q);
			if let Some(h) = params.get("min_height") {
				let h = h
					.parse()
					.map_err(|_| ErrorKind::RequestError("invalid minimum height".into()))?;
				// Default is genesis
				min_height = if h == 0 { None } else { Some(h) };
			}
			if let Some(h) = params.get("max_height") {
				let h = h
					.parse()
					.map_err(|_| ErrorKind::RequestError("invalid maximum height".into()))?;
				// Default is current head
				let head_height = chain
					.head()
					.map_err(|e| ErrorKind::Internal(format!("{}", e)))?
					.height;
				max_height = if h >= head_height { None } else { Some(h) };
			}
		}

		let kernel = chain
			.get_kernel_height(&excess, min_height, max_height)
			.map_err(|e| ErrorKind::Internal(format!("{}", e)))?
			.map(|(tx_kernel, height, mmr_index)| LocatedTxKernel {
				tx_kernel,
				height,
				mmr_index,
			});
		Ok(kernel)
	}

	pub fn get_all_kernels(
		&self,
		min_height: u64,
		max_height: u64,
	) -> Result<Vec<LocatedTxKernel>, Error> {
		let chain = w(&self.chain)?;
		let kernels = chain.get_all_kernels(min_height, max_height)?;
		let mut located_kernels = vec![];
		for kernel in kernels {
			located_kernels.push(LocatedTxKernel {
				tx_kernel: kernel.0,
				height: kernel.1,
				mmr_index: kernel.2,
			});
		}

		Ok(located_kernels)
	}

	pub fn get_kernels_v2(&self, excess: Vec<String>) -> Result<Vec<u64>, Error> {
		let excess = {
			let mut ret = vec![];
			for ex in excess {
				let ex = util::from_hex(&ex)
					.map_err(|_| ErrorKind::RequestError("invalid excess hex".into()))?;
				if ex.len() != 33 {
					return Err(ErrorKind::RequestError("invalid excess length".into()).into());
				}

				let ex = Commitment::from_vec(ex);
				ret.push(ex.clone());
			}
			ret
		};

		let chain = w(&self.chain)?;
		chain
			.get_kernel_heights(excess)
			.map_err(|e| ErrorKind::Internal(format!("{}", e)).into())
	}

	pub fn get_kernel_v2(
		&self,
		excess: String,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<LocatedTxKernel, Error> {
		let excess = util::from_hex(&excess)
			.map_err(|_| ErrorKind::RequestError("invalid excess hex".into()))?;
		if excess.len() != 33 {
			return Err(ErrorKind::RequestError("invalid excess length".into()).into());
		}
		let excess = Commitment::from_vec(excess);

		let chain = w(&self.chain)?;
		let kernel = chain
			.get_kernel_height(&excess, min_height, max_height)
			.map_err(|e| ErrorKind::Internal(format!("{}", e)))?
			.map(|(tx_kernel, height, mmr_index)| LocatedTxKernel {
				tx_kernel,
				height,
				mmr_index,
			});
		kernel.ok_or_else(|| ErrorKind::NotFound.into())
	}
}

impl Handler for KernelHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		result_to_response(self.get_kernel(req))
	}
}
