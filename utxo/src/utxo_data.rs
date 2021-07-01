// Copyright 2021 The BitcoinMW Developers
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

// Main entry point for loading/processing BTC UTXOs.

extern crate byteorder;
extern crate rust_base58;

use crate::error::Error;
use crate::error::ErrorKind;
use crate::utxo_constants::CHUNK_SIZE;
use crate::utxo_constants::INDEX_SIZE;
use crate::utxo_constants::TESTNET_DATA_SIZE;
use crate::utxo_constants::TESTNET_INDEX_HASHES;
use crate::utxo_constants::TESTNET_SHA256_HASH;
use bech32::ToBase32;
use bitvec::prelude::*;
use byte_tools::copy;
use byteorder::{LittleEndian, ReadBytesExt};
use grin_util::address_util::encode;
use grin_util::address_util::get_address;
use grin_util::encode_addr;
use grin_util::FLAG_BECH32_ADDRESS;
use grin_util::FLAG_LEGACY_ADDRESS;
use grin_util::FLAG_P2SH_ADDRESS;
use sha2::Digest;
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::num::TryFromIntError;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

/// Chain type enum
#[derive(Debug)]
pub enum ChainType {
	Testnet,
	Mainnet,
	Other,
	Bypass,
}

/// Information about the download of an index
#[derive(Debug)]
pub struct DownloadInfo {
	pub index: u8,
	pub last_part: u16,
	pub last_request: u128,
}

/// This is the main UtxoData structure used to hold the BTC Utxos.
/// There are two main data structures:
/// 1.) the 'data' Vec. This vector contains all the raw data of the BTC
/// Utxo set. The 'short_count' is the number of addresses that can be
/// encoded in 20 bytes of data and the 'long_count' is the number of addresses
/// that can be encoded in 32 bytes of data (for instance p2wsh addresses).
/// Next to each address is a 6 byte
/// piece of data that includes the number of satoshis in that address at the
/// time of the snapshot and a flag indicating what type of address this is
/// (legacy, p2sh, or bech32). These values are sorted so that binary search
/// can be used to quickly obtain a particular address, but also indexing is
/// allowed. The entire UTXO data that is needed is stored in around 700 - 800 MB
/// The data may look something like this:
/// [20 bytes of address data][6 bytes of satoshis/flags]
/// [20 bytes of address data][6 bytes of satoshis/flags]
/// ...
/// [32 bytes of address data][6 bytes of satoshis/flags]
/// [32 bytes of address data][6 bytes of satoshis/flags]
/// ...
/// [80 bytes of address data][6 bytes of satoshis/flags]
/// [80 bytes of address data][6 bytes of satoshis/flags]
/// ...
/// 2.) The claims_bitmap. This is a bitvec protected by a mutex.
/// It is used to store the status of claims on these addreses.
/// Care must be taken to deal with forks/reorgs.
/// Also, on startup, it must be reset based on the kernel data which is
/// permanently peristed by the node.
#[derive(Debug)]
pub struct UtxoData {
	chain_type: ChainType,
	pub claims_bitmap: Arc<Mutex<BitVec>>,
	tmp_bitvec: BitVec,
	pending: HashMap<String, DownloadInfo>,
	data: Vec<u8>,
	short_count: u32,
	long_count: u32,
	v1plus_count: u32,
	loading_complete: bool,
}

// implementation of the UtxoData
impl UtxoData {
	// read sats from a byte array resetting any flags
	fn read_sats(&self, bytes: &[u8]) -> Result<u64, Error> {
		let mut ret = self.read_num(bytes)?;
		ret &= !FLAG_LEGACY_ADDRESS;
		ret &= !FLAG_P2SH_ADDRESS;
		ret &= !FLAG_BECH32_ADDRESS;
		Ok(ret)
	}

	// read the raw number from a 6 byte little endian byte array
	fn read_num(&self, bytes: &[u8]) -> Result<u64, Error> {
		let mut vec = bytes.to_vec();
		vec.append(&mut vec![0x0, 0x0]);
		let num = Cursor::new(vec).read_u64::<LittleEndian>()?;
		Ok(num)
	}

	// what percentage of loading has taken place.
	pub fn load_percentage(&self) -> u8 {
		if self.is_loaded() {
			u8::MAX
		} else {
			let len = self.tmp_bitvec.len();

			if len == 0 {
				return 0;
			}

			let mut count = 0;
			for i in 0..len {
				if self.tmp_bitvec[i] {
					count += 1;
				}
			}
			let res: Result<u8, TryFromIntError> = ((count as usize * 100) / len).try_into();
			if res.is_err() {
				0
			} else {
				res.unwrap()
			}
		}
	}

	// get the max index for syncing (network dependant)
	// indexes refer to 16 mb chunks of the file
	pub fn get_max_index(&self) -> u8 {
		match &self.chain_type {
			ChainType::Mainnet => 0, // TODO: Update for mainnet
			ChainType::Testnet => 56,
			_ => 0, // other network types can't sync. Must use file
		}
	}

	// reset an index. This is called if the hash doesn't match so the next host can start over.
	pub fn reset_index(&mut self, index: u8) {
		for i in 0..32 {
			let offset = (index as usize * (16 * 1024 * 1024) / CHUNK_SIZE as usize) + i as usize;
			// check for last index being shorter.
			if offset < self.tmp_bitvec.len() {
				self.tmp_bitvec.set(offset, false);
			}
		}
	}

	// check a hash to make sure the data sent from a host is valid. Ban host if invalid.
	pub fn check_hash(&self, index: u8) -> bool {
		let offset = index as usize * 16 * 1024 * 1024;
		let len = if index == self.get_max_index() - 1 {
			(self.get_last_chunk_size(CHUNK_SIZE)
				+ (self.get_last_part_count(CHUNK_SIZE) - 1) as u32 * CHUNK_SIZE) as usize
		} else {
			INDEX_SIZE as usize
		};
		let data_slice = &self.data[offset..(offset + len)];

		let mut hasher = Sha256::new();
		hasher.update(data_slice);
		let hash = hasher.finalize();
		if format!("{:x}", hash) != TESTNET_INDEX_HASHES[index as usize] {
			error!(
				"hash of index[{}]='{:x}' != {}",
				index, hash, TESTNET_INDEX_HASHES[index as usize]
			);
			false
		} else {
			true
		}
	}

	// add part of the data sent by a host to our data.
	pub fn add_part(
		&mut self,
		data: Vec<u8>,
		index: u8,
		part: u16,
		address: String,
	) -> Result<(), Error> {
		let download_info = self.pending.get(&address);
		if download_info.is_none() {
			Err(ErrorKind::InvalidPeer(address).into())
		} else if download_info.unwrap().index != index {
			Err(ErrorKind::InvalidPeer(address).into())
		} else if data.len() > CHUNK_SIZE as usize {
			Err(ErrorKind::IndexOutOfBounds.into())
		} else {
			let offset = index as usize * 16 * 1024 * 1024 + part as usize * CHUNK_SIZE as usize;
			copy(&data, &mut self.data[offset..]);
			self.tmp_bitvec.set(
				(index as usize * (16 * 1024 * 1024) / CHUNK_SIZE as usize) + part as usize,
				true,
			);
			Ok(())
		}
	}

	// check if download of a particular part is complete. If yes, proceed to next part of d/l
	pub fn verify_part(&self, index: u8, part: u16) -> bool {
		let val = self
			.tmp_bitvec
			.get((index as usize * (16 * 1024 * 1024) / CHUNK_SIZE as usize) + part as usize);

		if val.is_none() {
			return false;
		} else {
			return *val.unwrap();
		}
	}

	// write the data to the file as it has been confirmed
	pub fn finalize_file(&mut self, location: String) -> Result<(), Error> {
		info!("Writing binary file to [{}]", location);
		let mut file = File::create(location)?;
		file.write_all(&self.data[..])?;
		info!("Writing of file complete!");
		self.data = Vec::new();
		Ok(())
	}

	// setup a temporary bitvec to check status of partial download.
	pub fn setup_tmp_data(&mut self, chunk_size: u32) {
		self.data = Vec::new();
		match self.chain_type {
			ChainType::Testnet => {
				self.data.resize(TESTNET_DATA_SIZE, 0);
				self.tmp_bitvec
					.resize((TESTNET_DATA_SIZE / chunk_size as usize) + 1, false);
			}
			_ => {} // other networks currently unimplemented
		}
	}

	// get the number of parts in the last index
	pub fn get_last_part_count(&self, chunk_size: u32) -> u16 {
		match self.chain_type {
			ChainType::Testnet => {
				1 + ((TESTNET_DATA_SIZE % INDEX_SIZE as usize) as u32 / chunk_size as u32) as u16
			}
			_ => 0, // other networks currently unimplemented
		}
	}

	// return the chunk size
	pub fn get_last_chunk_size(&self, chunk_size: u32) -> u32 {
		match self.chain_type {
			ChainType::Testnet => ((TESTNET_DATA_SIZE) as u32 % chunk_size) as u32,
			_ => 0, // other networks currently unimplemented
		}
	}

	// get a chunk of data for sync purposes
	pub fn get_chunk(&self, index: u8, part: u16, chunk_size: u32) -> Vec<u8> {
		let offset = (index as usize) * 16 * 1024 * 1024 + (part as usize) * (CHUNK_SIZE as usize);
		let offset_end = offset + (chunk_size as usize);
		let slice = &self.data[offset..offset_end];

		slice.to_vec()
	}

	// indicate whether or not the data has been loaded
	pub fn is_loaded(&self) -> bool {
		self.loading_complete
	}

	// get the offset for a particular index taking into consider if it's
	// a long/short address, etc.
	fn get_offset(&self, index: u32) -> Result<usize, Error> {
		if !self.loading_complete {
			return Err(ErrorKind::NotLoaded.into());
		}
		if index < self.short_count {
			// this is a short address
			Ok((index * 26 + 16) as usize)
		} else if index < (self.short_count + self.long_count) {
			// this is a long address
			Ok((self.short_count * 26 + (index - self.short_count) * 38 + 16) as usize)
		} else if index < (self.short_count + self.long_count + self.v1plus_count) {
			// this is a bech32 v1plus address
			Ok((self.short_count * 26
				+ self.long_count * 38
				+ (index - (self.short_count + self.long_count)) * 80
				+ 16) as usize)
		} else {
			// index out of bounds
			Err(ErrorKind::IndexOutOfBounds.into())
		}
	}

	// compare an address as a string with the address stored in an index
	fn cmp_index(&self, address: &String, index: u32) -> Result<i8, Error> {
		if !self.loading_complete {
			return Err(ErrorKind::NotLoaded.into());
		}
		// get offset in the data array
		let offset = self.get_offset(index)?;
		// end point is different for long/short addresses
		let end = if index < self.short_count {
			offset + 20
		} else if index < self.short_count + self.long_count {
			offset + 32
		} else {
			offset + 74
		};
		// get the slice we need to compare
		let test_slice = &self.data[offset..end];
		// encode passed in address
		let vec = &encode_addr(address.to_string())?[0..(end - offset)];

		// do the comparison
		let ret = Ok(match vec.cmp(&test_slice.to_vec()) {
			Ordering::Equal => 0,
			Ordering::Less => 1,
			Ordering::Greater => -1,
		});
		ret
	}

	// load the binary file from the specified location
	pub fn load_binary(&mut self, binary: &str) -> Result<(), Error> {
		info!("loading binary at {}", binary);

		// check if the binary exists. It it doesn't we must halt
		if !Path::new(binary).exists() {
			return Err(ErrorKind::FileNotFound(binary.to_string()).into());
		}

		let mut file = File::open(binary.to_string())?;
		let len = std::fs::metadata(binary.to_string())?.len();
		let mut data = Vec::new();
		data.resize(len.try_into().unwrap(), 0);
		file.read(&mut data)?;
		let mut hasher = Sha256::new();
		hasher.update(&data);
		let hash = hasher.finalize();

		// check hash of binary if it's testnet/mainnet
		match self.chain_type {
			ChainType::Testnet => {
				if format!("{:x}", hash) != TESTNET_SHA256_HASH {
					error!(
						"utxo binary checksum did not match. Found [{}], expected [{}]. Halting!",
						format!("{:x}", hash),
						TESTNET_SHA256_HASH,
					);
					std::process::exit(-1);
				}
			}
			ChainType::Mainnet => {}
			_ => {}
		}

		let mut tmp = [0 as u8; 4];

		copy(&data[0..4], &mut tmp);
		let short_count = Cursor::new(tmp).read_u32::<LittleEndian>()?;

		copy(&data[4..8], &mut tmp);
		let long_count = Cursor::new(tmp).read_u32::<LittleEndian>()?;

		copy(&data[8..12], &mut tmp);
		let v1plus_count = Cursor::new(tmp).read_u32::<LittleEndian>()?;

		// note four bytes reserved here.

		self.data = data;
		self.short_count = short_count;
		self.long_count = long_count;
		self.v1plus_count = v1plus_count;

		// Initialize the claims_bitmap. All false, this is updated by chain.rs
		// Based on kernels
		let mut claims_bitmap: BitVec = BitVec::new();
		claims_bitmap.resize(
			short_count as usize + long_count as usize + v1plus_count as usize,
			false,
		);
		let claims_bitmap = Arc::new(Mutex::new(claims_bitmap));
		self.claims_bitmap = claims_bitmap;
		self.loading_complete = true;

		// now deallocate the bitvec to save space
		self.tmp_bitvec = BitVec::new();

		info!("loading of binary complete!");
		Ok(())
	}

	pub fn get_pending(&mut self) -> &mut HashMap<String, DownloadInfo> {
		&mut self.pending
	}

	// obtain a new UtxoData struct based on the binary input file
	pub fn new(chain_type: ChainType) -> Result<UtxoData, Error> {
		// init with no data to start with
		let claims_bitmap = Arc::new(Mutex::new(BitVec::new()));
		let data = Vec::new();
		let short_count = 0;
		let long_count = 0;
		let v1plus_count = 0;
		let loading_complete = false;
		let tmp_bitvec = BitVec::new();
		let pending = HashMap::new();

		Ok(UtxoData {
			chain_type,
			claims_bitmap,
			tmp_bitvec,
			pending,
			data,
			short_count,
			long_count,
			v1plus_count,
			loading_complete,
		})
	}

	// perform a binary search to find the index of the specified address
	pub fn get_index(&self, address: String) -> Result<u32, Error> {
		if !self.loading_complete {
			return Err(ErrorKind::NotLoaded.into());
		}
		let mut min;
		let mut max;

		// depending on the address length we only search part of the
		// data vec.
		if address.starts_with("b") && !address.starts_with("bc1q") {
			// bech32 v1plus
			min = self.short_count + self.long_count;
			max = self.short_count + self.long_count + self.v1plus_count - 1;
		} else if address.len() > 42 {
			// long address
			if self.long_count == 0 {
				return Err(ErrorKind::AddressNotFound.into());
			}
			min = self.short_count;
			max = self.short_count + self.long_count - 1;
		} else {
			// short address
			if self.short_count == 0 {
				return Err(ErrorKind::AddressNotFound.into());
			}
			min = 0;
			max = self.short_count - 1;
		}

		// loop until we find it or we know it's not there
		loop {
			// set the mid point
			let test = (min + max) / 2;

			// test to see if we found it, or less or greater
			let res = self.cmp_index(&address, test)?;

			// check if it's not found
			if max <= min && res != 0 {
				return Err(ErrorKind::AddressNotFound.into());
			}

			if res > 0 {
				max = test - 1;
			} else if res < 0 {
				min = test + 1;
			} else {
				// found our index
				return Ok(test);
			}
		}
	}

	// get the sats based on an input address
	pub fn get_sats_by_address(&self, address: String) -> Result<u64, Error> {
		if !self.loading_complete {
			return Err(ErrorKind::NotLoaded.into());
		}
		let index = self.get_index(address)?;
		self.get_sats_by_index(index)
	}

	// get the address by index
	pub fn get_address(&self, index: u32) -> Result<String, Error> {
		if !self.loading_complete {
			return Err(ErrorKind::NotLoaded.into());
		}
		let short_count = self.short_count;
		let long_count = self.long_count;
		let offset = self.get_offset(index)?;
		if index < short_count {
			// it's a short address
			let num_slice = &self.data[(offset + 20)..(offset + 26)];
			let num = self.read_num(num_slice)?;
			let addr_slice = &self.data[offset..(offset + 20)];
			// check address type
			let address = if num & FLAG_LEGACY_ADDRESS != 0 {
				let mut prefixed = [0; 21];
				prefixed[0] = 0x00;
				prefixed[1..].copy_from_slice(&addr_slice);
				get_address(prefixed.to_vec())
			} else if num & FLAG_P2SH_ADDRESS != 0 {
				let mut prefixed = [0; 21];
				prefixed[0] = 0x05;
				prefixed[1..].copy_from_slice(&addr_slice);
				get_address(prefixed.to_vec())
			} else if num & FLAG_BECH32_ADDRESS != 0 {
				let u5buf = addr_slice.to_vec().to_base32();
				let mut prefixed: [bech32::u5; 33] = [bech32::u5::try_from_u8(0x00)?; 33];
				prefixed[1..].copy_from_slice(&u5buf[..32]);
				encode("bc", prefixed.to_vec())
			} else {
				return Err(ErrorKind::UnknownAddressType.into());
			}?;

			Ok(address)
		} else if index < (short_count + long_count) {
			// it's a long address (always bech32)
			let addr_slice = &self.data[offset..(offset + 32)];
			let addr_b32 = addr_slice.to_base32();
			let mut prefixed: [bech32::u5; 53] = [bech32::u5::try_from_u8(0x00)?; 53];
			prefixed[1..].copy_from_slice(&addr_b32[..52]);
			Ok(encode("bc", prefixed.to_vec())?)
		} else {
			// out of bounds
			Err(ErrorKind::IndexOutOfBounds.into())
		}
	}

	// get the satoshis by index
	pub fn get_sats_by_index(&self, index: u32) -> Result<u64, Error> {
		if !self.loading_complete {
			return Err(ErrorKind::NotLoaded.into());
		}

		let short_count = self.short_count;
		let long_count = self.long_count;
		let v1plus_count = self.v1plus_count;

		if index < short_count {
			// it's a short index
			let offset = index * 26 + 16;
			Ok(self.read_sats(&self.data[((offset + 20) as usize..(offset + 26) as usize)])?)
		} else if index < (short_count + long_count) {
			// it's a long index
			let offset = short_count * 26 + (index - short_count) * 38 + 16;
			Ok(self.read_sats(&self.data[((offset + 32) as usize..(offset + 38) as usize)])?)
		} else if index < (short_count + long_count + v1plus_count) {
			let offset =
				short_count * 26 + long_count * 38 + (index - (short_count + long_count)) * 80 + 16;
			Ok(self.read_sats(&self.data[((offset + 74) as usize..(offset + 80) as usize)])?)
		} else {
			// out of bounds
			Err(ErrorKind::IndexOutOfBounds.into())
		}
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn test_utxo_data() {
		use crate::utxo_data::ChainType;
		use crate::utxo_data::UtxoData;

		let mut utxo_data = UtxoData::new(ChainType::Bypass).unwrap();
		assert_eq!(
			utxo_data
				.load_binary("./tests/resources/test_bin.bin")
				.is_err(),
			false
		);

		// try an unknown address
		let res = utxo_data.get_index("14Hte8Pwg8g1fZwVhUMYVEBEDh8sSyuNPr".to_string());
		assert_eq!(res.is_err(), true);

		let res = utxo_data.get_index("1BTsxjF9rXtFvUZ2UFditbeUpohGgKCxUt".to_string());
		println!("res={:?}", res);
		assert_eq!(res.is_ok(), true);

		// loop through and obtain all addresses in our utxo_data
		let mut i = 0;
		let mut vec = Vec::new();
		loop {
			let x = utxo_data.get_address(i);
			if x.is_err() {
				break;
			}
			vec.insert(0, x.unwrap());
			i += 1;
		}

		// we should have found 942 addresses based on this data set
		assert_eq!(i, 942);

		for x in 0..942 {
			// loop through each one and check that all data is
			// consistent
			let index = utxo_data.get_index(vec[x].clone()).unwrap();
			let address = utxo_data.get_address(index).unwrap();
			let sats_by_address = utxo_data.get_sats_by_address(vec[x].clone()).unwrap();
			let sats_by_index = utxo_data.get_sats_by_index(index).unwrap();
			assert_eq!(address, vec[x].clone());
			assert_eq!(index, (942 - x as u32) - 1);
			assert_eq!(sats_by_index, sats_by_address);
			// most are 5000000000 (coinbase, but a few others we test)
			if index == 928 {
				assert_eq!(sats_by_index, 1000000000);
			} else if index == 760 {
				assert_eq!(sats_by_index, 2500000000);
			} else if index == 719 {
				assert_eq!(sats_by_index, 2400000000);
			} else if index == 500 || index == 300 {
				assert_eq!(sats_by_index, 5000000000);
			}
		}
	}

	#[test]
	fn test_utxo_data_with_bech32v1plus() -> Result<(), crate::utxo_data::Error> {
		use crate::utxo_data::ChainType;
		use crate::utxo_data::UtxoData;

		let mut utxo_data = UtxoData::new(ChainType::Bypass).unwrap();
		assert_eq!(
			utxo_data
				.load_binary("./tests/resources/test_bin2.bin")
				.is_err(),
			false
		);

		// try an unknown address
		let res = utxo_data.get_index("14Hte8Pwg8g1fZwVhUMYVEBEDh8sSyuNPr".to_string());
		assert_eq!(res.is_err(), true);

		// try a knonwn address
		let res = utxo_data.get_index("bc1qp32dxlajlyjznqwqkxd72t4ksa56jn700ucvmh".to_string());
		assert_eq!(res.is_err(), false);
		assert_eq!(res.unwrap(), 0);

		// try v1plus addresses
		let res = utxo_data.get_index("bc1zqyqsywvzqe".to_string());
		assert_eq!(res.is_err(), false);
		assert_eq!(res.unwrap(), 1);

		let res = utxo_data.get_index("bc1pxqsrzgpjyqejqdpqx5srvgphyquzqwgdd7yg9".to_string());
		assert_eq!(res.is_err(), false);
		assert_eq!(res.unwrap(), 2);

		// try some invalid v1plus addresses
		let res = utxo_data.get_index("bc1pxysyzgrpyp9zq63q2vs8xgp3ypdjqhguvkagn".to_string());
		assert_eq!(res.is_err(), true);

		let res = utxo_data.get_index(
			"bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ss52r5n8".to_string(),
		);
		assert_eq!(res.is_err(), true);

		assert_eq!(utxo_data.get_sats_by_index(0)?, 10000000000);
		assert_eq!(utxo_data.get_sats_by_index(1)?, 10200000000);
		assert_eq!(utxo_data.get_sats_by_index(2)?, 10100000000);
		// get sats

		Ok(())
	}
}
