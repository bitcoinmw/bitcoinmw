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

// These functions are for syncing the BTC utxo set

use crate::common::types::Error;
use crate::p2p::msg::BtcUtxoSetRequest;
use crate::p2p::Peer;
use crate::p2p::{self, types::ReasonForBan};
pub use bmw_utxo::utxo_constants::CHUNK_SIZE;
use bmw_utxo::utxo_constants::PARTS_PER_INDEX;
use bmw_utxo::utxo_data::DownloadInfo;
use bmw_utxo::utxo_data::UtxoData;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// status of the index being downloaded
enum IndexStatus {
	UnInitiated,
	Initiated,
	Complete,
}

// main structure for status of the UtxoSync
pub struct UtxoSync {
	// copy of peers currently known
	peers: Arc<p2p::Peers>,
	// status of the indices being downloaded
	index_status: HashMap<u8, (IndexStatus, String)>,
}

impl UtxoSync {
	// create a new instance of UtxoSync
	pub fn new(peers: Arc<p2p::Peers>) -> UtxoSync {
		let index_status = HashMap::new();
		UtxoSync {
			peers,
			index_status,
		}
	}

	// process the next part of the index being downloaded
	pub fn process_next(
		&mut self,
		last_part: u16,
		index: u8,
		max_index: u8,
		time_now: u128,
		utxo_data: &mut UtxoData,
		address: String,
		peer: Arc<Peer>,
	) -> Result<(), Error> {
		// if there's still more parts to download do so.
		if ((last_part + 1) as u32) < PARTS_PER_INDEX {
			// special logic to check last index which has less parts
			if !(index == max_index - 1
				&& last_part >= utxo_data.get_last_part_count(CHUNK_SIZE) - 1)
			{
				let chunk_size = if index == max_index - 1
					&& last_part == utxo_data.get_last_part_count(CHUNK_SIZE) - 2
				{
					utxo_data.get_last_chunk_size(CHUNK_SIZE)
				} else {
					CHUNK_SIZE
				}; // size of this chunk

				// build the request struct
				let req = BtcUtxoSetRequest {
					index,
					part: last_part + 1,
					chunk_size,
				};
				info!("requesting {:?} from {:?}", req, peer.info.addr);
				// send the request to the peer
				peer.send_utxo_request(req)?;

				// insert the info into the pending hashmap
				utxo_data.get_pending().insert(
					address,
					DownloadInfo {
						index,
						last_part: last_part + 1,
						last_request: time_now,
					},
				);
			} else {
				// check that the hash is correct since we've downloaded all parts
				self.validate_hash(index, utxo_data, &address, &peer)?;
			}
		} else {
			// check that the hash is correct since we've downloaded all parts
			self.validate_hash(index, utxo_data, &address, &peer)?;
		}
		Ok(())
	}

	// make sure this index has the correct hash
	fn validate_hash(
		&mut self,
		index: u8,
		utxo_data: &mut UtxoData,
		address: &String,
		peer: &Arc<Peer>,
	) -> Result<(), Error> {
		// is it valid?
		let valid = utxo_data.check_hash(index);

		if valid {
			// it's valid so we can update the structures so the next part can be processed
			utxo_data.get_pending().remove(&address.clone());
			self.index_status
				.insert(index, (IndexStatus::Complete, "".to_string()));
		} else {
			// it wasn't valid, reset the index and ban this peer
			utxo_data.reset_index(index);
			self.peers
				.ban_peer(peer.info.addr.clone(), ReasonForBan::BadBTCUtxoSet)?;
		}
		Ok(())
	}

	// try to process a pending peer
	pub fn try_process_pending_peer(
		&mut self,
		utxo_data: &mut UtxoData,
		address: String,
		peer: Arc<Peer>,
	) -> Result<bool, Error> {
		let max_index = utxo_data.get_max_index();
		let download_info = utxo_data.get_pending().get(&address);
		if download_info.is_none() {
			// this is not a pending peer, return false
			return Ok(false);
		}

		// current time in ms
		let time_now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
		let download_info = download_info.unwrap();
		let index = download_info.index;
		let last_part = download_info.last_part;

		// if we can verify that the last part was downloaded, process the next
		if utxo_data.verify_part(index, last_part) {
			self.process_next(
				last_part,
				index,
				max_index,
				time_now,
				utxo_data,
				address.clone(),
				peer,
			)?;
		}

		// return true since we were able to confirm this is a pending peer
		Ok(true)
	}

	// start a peer on a new index
	pub fn init_peer(
		&mut self,
		peer: Arc<Peer>,
		index: u8,
		address: String,
		pending: &mut HashMap<String, DownloadInfo>,
	) -> Result<(), Error> {
		let req = BtcUtxoSetRequest {
			index,
			part: 0,
			chunk_size: CHUNK_SIZE,
		};
		info!("requesting {:?} from {:?}", req, peer.info.addr);
		peer.send_utxo_request(req)?;

		// last_part is 0 since this is the first part downloaded.
		pending.insert(
			address.to_string(),
			DownloadInfo {
				index,
				last_part: 0,
				last_request: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
			},
		);
		self.index_status
			.insert(index, (IndexStatus::Initiated, address.to_string()));
		Ok(())
	}

	// this peer is idle. Have it start downloading something if possible.
	pub fn process_idle_peer(
		&mut self,
		utxo_data: &mut UtxoData,
		peer: Arc<Peer>,
		address: &String,
		binary_location: String,
	) -> Result<bool, Error> {
		let max_index = utxo_data.get_max_index();
		let pending = utxo_data.get_pending();

		let mut complete = true;
		// iterate through the indices and find one that's either un-initiated or one that timed
		// out. Timeout is if the previous peer hasn't completed any parts for 60 seconds.
		for i in 0..max_index {
			let cur_status = self.index_status.get(&i).unwrap();
			match cur_status.0 {
				IndexStatus::Complete => {
					// do nothing, continue loop
				}
				IndexStatus::Initiated => {
					// this index has been initiated but check if it's timed out
					let time_now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
					let download_info = pending.get(&cur_status.1);
					if download_info.is_some() {
						let download_info = download_info.unwrap();
						if time_now - download_info.last_request > 60_000 {
							// last peer timed out, let current peer try
							warn!(
								"Peer [{}] timed out, replacing with new peer [{}]",
								cur_status.1, peer.info.addr,
							);
							pending.remove(&cur_status.1);
							self.init_peer(peer, i, address.to_string(), pending)?;
							return Ok(false);
						}
					}
					complete = false;
				}
				IndexStatus::UnInitiated => {
					// this index needs to be initiated
					self.init_peer(peer, i, address.to_string(), pending)?;
					return Ok(false);
				}
			}
		}

		if complete {
			// complete. Now write file.
			info!("Download of UtxoData complete! Writing file.");
			let res = (*utxo_data).finalize_file(binary_location.clone());
			if res.is_err() {
				error!("ERROR: writing the file generated error: {:?}", res);
			}
			return Ok(true);
		}

		return Ok(false);
	}

	// main entry point for utxo_sync
	// keep trying until true is returned
	pub fn check_run(
		&mut self,
		utxo_data: &mut UtxoData,
		binary_location: String,
	) -> Result<bool, Error> {
		let max_index = utxo_data.get_max_index();
		// check if this is the first time through the loop, if so init the index_status
		if self.index_status.len() != max_index as usize {
			for i in 0..max_index {
				self.index_status
					.insert(i, (IndexStatus::UnInitiated, "".to_string()));
			}
		}

		// iterate through peers
		let peer_vec = self.peers.get_peer_vec();
		for peer in peer_vec {
			if peer.is_connected() {
				// peer is connected, try to give it work or check it's status.
				let address = format!("{:?}", peer.info.addr);
				if !self.try_process_pending_peer(utxo_data, address.clone(), peer.clone())? {
					// this was not a pending peer, so give it work as an idle peer
					if self.process_idle_peer(
						utxo_data,
						peer,
						&address.clone(),
						binary_location.clone(),
					)? {
						// this means there's nothing more to do, return true here
						return Ok(true);
					}
				}
			}
		}

		Ok(false)
	}
}
