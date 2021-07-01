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

use byte_tools::copy;
use failure::{Context, Fail};
use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};

const EMPTY: u8 = 0;
const OCCUPIED: u8 = 1;
const DELETED: u8 = 2;

/// Basic statistics for this static hash
#[derive(Debug, Clone)]
pub struct StaticHashStats {
	/// Max elements that have ever been in this table at one given time
	pub max_elements: u64,
	/// Current number of elements in the table
	pub cur_elements: u64,
	/// Total of times the 'get' function is called
	pub access_count: u64,
	/// Total of node visits on a get (collision results in at least two node visits)
	/// Note that if errors are returned the get is not counted.
	pub total_node_reads: u64,
	/// Worst case visits
	pub worst_case_visits: u64,
}

impl StaticHashStats {
	fn reset(&mut self) {
		// can't reset other fields.
		self.access_count = 0;
		self.total_node_reads = 0;
		self.worst_case_visits = 0;
	}
}

/// Iterator
pub struct StaticHashIterator {
	pos: u64,
	hashtable: StaticHash,
}

impl StaticHashIterator {
	/// Create a new StaticHashIterator
	pub fn new(hashtable: StaticHash) -> Result<StaticHashIterator, Error> {
		Ok(StaticHashIterator { pos: 0, hashtable })
	}

	/// Get the next element in the iterator
	pub fn next(&mut self, key: &mut [u8], value: &mut [u8]) -> Result<bool, Error> {
		loop {
			if self.pos >= self.hashtable.max_entries {
				break;
			}
			let overhead_byte = self.hashtable.get_overhead_byte(self.pos);
			if overhead_byte == OCCUPIED {
				let res = self.hashtable.copy_key(key, self.pos);
				if res.is_ok() {
					let res = self.hashtable.copy_value(value, self.pos);
					if res.is_ok() {
						self.pos += 1;
						return Ok(true);
					} else {
						return Err(ErrorKind::OtherError("error copying value".to_string()).into());
					}
				} else {
					return Err(ErrorKind::OtherError("error copying key".to_string()).into());
				}
			}

			self.pos += 1;
		}

		Ok(false)
	}
}

/// Static hash object. A hashtable with fixed size.
/// format of the hashtable:
/// [overhead byte: 0 - empty, 1 - occupied, 2 - deleted][key - key_len bytes][value - entry_len bytes]
#[derive(Clone)]
pub struct StaticHash {
	data: Vec<u8>,
	/// Max entries in this table
	pub max_entries: u64,
	key_len: u8,
	entry_len: u8,
	/// Maximum load factor allowed
	max_load_factor: f64,
	/// Basic statistics for this static hash
	pub stats: StaticHashStats,
}

#[derive(Hash)]
struct Key {
	data: Vec<u8>,
}

impl StaticHash {
	/// Create a new instance of StaticHash
	pub fn new(
		max_entries: usize,
		key_len: u8,
		entry_len: u8,
		max_load_factor: f64,
	) -> Result<StaticHash, Error> {
		if max_load_factor >= 1 as f64 || max_load_factor <= 0 as f64 {
			return Err(ErrorKind::InvalidMaxLoadCapacity.into());
		}
		let mut data = Vec::new();
		data.resize(max_entries * (1 + key_len + entry_len) as usize, 0);
		let max_entries = max_entries.try_into().unwrap_or(0);
		Ok(StaticHash {
			data,
			max_entries,
			key_len,
			entry_len,
			max_load_factor,
			stats: StaticHashStats {
				max_elements: 0,
				cur_elements: 0,
				access_count: 0,
				total_node_reads: 0,
				worst_case_visits: 0,
			},
		})
	}

	/// Return the current size of this static_hash
	pub fn size(&self) -> u64 {
		self.stats.cur_elements
	}

	/// Get this key
	pub fn get(&mut self, key: &[u8], value: &mut [u8]) -> Result<bool, Error> {
		if key.len() != self.key_len as usize {
			return Err(ErrorKind::BadKeyLen(key.len(), self.key_len).into());
		}
		if value.len() != self.entry_len as usize {
			return Err(ErrorKind::BadValueLen(value.len(), self.entry_len).into());
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY {
				return Ok(false);
			} else if ohb == OCCUPIED && self.cmp_key(key, entry) {
				let offset =
					(1 + self.key_len + self.entry_len) as u64 * entry + 1 + self.key_len as u64;
				copy(
					&self.data.as_slice()
						[offset as usize..offset as usize + self.entry_len as usize],
					value,
				);
				return Ok(true);
			}

			count += 1;
			if count > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count;
			}
		}
	}

	/// Put this value for specified key
	pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
		if key.len() != self.key_len as usize {
			return Err(ErrorKind::BadKeyLen(key.len(), self.key_len).into());
		}
		if value.len() != self.entry_len as usize {
			return Err(ErrorKind::BadValueLen(value.len(), self.entry_len).into());
		}
		if (self.stats.cur_elements + 1) as f64 / self.max_entries as f64 > self.max_load_factor {
			return Err(ErrorKind::MaxLoadCapacityExceeded.into());
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == EMPTY || ohb == DELETED {
				// empty spot
				self.set_overhead_byte(entry, OCCUPIED);
				self.set_key(entry, key);
				self.set_value(entry, value);
				self.stats.cur_elements += 1;
				if self.stats.cur_elements > self.stats.max_elements {
					self.stats.max_elements = self.stats.cur_elements;
				}
				break;
			}

			if ohb == OCCUPIED && self.cmp_key(key, entry) {
				// already present, overwrite value
				self.set_value(entry, value);
				break;
			}

			count += 1;
			if count > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count;
			}
		}
		Ok(())
	}

	/// Remove the speicifed key
	pub fn remove(&mut self, key: &[u8]) -> Result<bool, Error> {
		if key.len() != self.key_len as usize {
			return Err(ErrorKind::BadKeyLen(key.len(), self.key_len).into());
		}
		let hash = self.get_hash(key);
		let mut count = 0;
		loop {
			let entry = (hash + count) % self.max_entries;
			let ohb = self.get_overhead_byte(entry);
			if ohb == OCCUPIED {
				if self.cmp_key(key, entry) {
					// this is us, flag entry as deleted.
					self.set_overhead_byte(entry, DELETED);
					self.stats.cur_elements -= 1;
					return Ok(true);
				}
			// otherwise, this is not us, we continue
			} else if ohb == EMPTY {
				// we didn't find this entry.
				return Ok(false);
			} // otherwise, it's another deleted entry, we need to continue
			count += 1;
			if count > self.stats.worst_case_visits {
				self.stats.worst_case_visits = count;
			}
		}
	}

	/// Reset the stats fields
	pub fn reset_stats(&mut self) {
		self.stats.reset();
	}

	fn get_overhead_byte(&mut self, entry: u64) -> u8 {
		self.stats.total_node_reads += 1;
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry;
		self.data[offset as usize]
	}

	fn set_overhead_byte(&mut self, entry: u64, value: u8) {
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry;
		self.data[offset as usize] = value;
	}

	fn get_hash(&mut self, key: &[u8]) -> u64 {
		self.stats.access_count += 1;
		let mut hasher = DefaultHasher::new();
		Key { data: key.to_vec() }.hash(&mut hasher);
		hasher.finish() % self.max_entries
	}

	fn copy_key(&mut self, key: &mut [u8], entry: u64) -> Result<(), Error> {
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry + 1 as u64;
		copy(
			&self.data.as_slice()[(offset as usize)..((offset + self.key_len as u64) as usize)],
			key,
		);
		Ok(())
	}

	fn copy_value(&mut self, value: &mut [u8], entry: u64) -> Result<(), Error> {
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry + (1 + self.key_len) as u64;
		copy(
			&self.data.as_slice()[(offset as usize)..((offset + self.entry_len as u64) as usize)],
			value,
		);
		Ok(())
	}

	fn cmp_key(&mut self, key: &[u8], entry: u64) -> bool {
		let len = key.len();
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry + 1 as u64;
		for i in 0..len {
			if self.data[(offset + i as u64) as usize] != key[i] {
				return false;
			}
		}
		return true;
	}

	fn set_value(&mut self, entry: u64, value: &[u8]) {
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry + 1 + self.key_len as u64;
		copy(value, &mut self.data.as_mut_slice()[(offset as usize)..]);
	}

	fn set_key(&mut self, entry: u64, key: &[u8]) {
		let offset = (1 + self.key_len + self.entry_len) as u64 * entry + 1 as u64;
		copy(key, &mut self.data.as_mut_slice()[(offset as usize)..]);
	}
}

/// Errors that occur in the Static hash
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

/// Errors associated with the static_hash
#[derive(Debug, Fail)]
pub enum ErrorKind {
	/// Bad key len
	#[fail(display = "Keylen not correct {} != {}", _0, _1)]
	BadKeyLen(usize, u8),
	/// Bad value len
	#[fail(display = "Valuelen not correct {} != {}", _0, _1)]
	BadValueLen(usize, u8),
	/// Other error
	#[fail(display = "Other error {}", _0)]
	OtherError(String),
	/// Max Load Capacity has been exceeded
	#[fail(display = "Max Load Capacity Exceeded")]
	MaxLoadCapacityExceeded,
	/// Invalid MaxLoadCapacity
	#[fail(display = "Invalid Max Load Capacity")]
	InvalidMaxLoadCapacity,
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_static_hash() {
		let mut hashtable = StaticHash::new(10, 8, 8, 0.9).unwrap();
		let key1 = [1, 2, 3, 4, 5, 6, 7, 8];
		let key2 = [8, 7, 6, 5, 4, 3, 2, 1];

		let value1 = [1, 1, 1, 1, 1, 1, 1, 1];
		let value2 = [2, 2, 2, 2, 2, 2, 2, 2];
		let res1 = hashtable.put(&key1, &value1);
		let res2 = hashtable.put(&key2, &value2);
		assert_eq!(res1.is_err(), false);
		assert_eq!(res2.is_err(), false);

		let mut value_read1 = [0, 0, 0, 0, 0, 0, 0, 0];
		let mut value_read2 = [0, 0, 0, 0, 0, 0, 0, 0];

		let get1 = hashtable.get(&key1, &mut value_read1).unwrap();
		let get2 = hashtable.get(&key2, &mut value_read2).unwrap();

		assert_eq!(get1, true);
		assert_eq!(get2, true);

		assert_eq!(value1, value_read1);
		assert_eq!(value2, value_read2);

		// test wrong sizes
		let badkey = [1, 2, 3];
		let bad_put = hashtable.put(&badkey, &value1);
		assert_eq!(bad_put.is_err(), true);

		let badvalue = [4, 5, 6];
		let bad_put = hashtable.put(&key1, &badvalue);
		assert_eq!(bad_put.is_err(), true);

		// overwrite value

		let mut hashtable = StaticHash::new(30, 3, 3, 0.9).unwrap();

		let key1 = [3, 3, 3];
		let value1 = [4, 4, 4];
		let value2 = [5, 5, 5];

		let res1 = hashtable.put(&key1, &value1);
		let res2 = hashtable.put(&key1, &value2);
		assert_eq!(res1.is_err(), false);
		assert_eq!(res2.is_err(), false);

		let mut value_read = [0, 0, 0];
		let res = hashtable.get(&key1, &mut value_read);
		assert_eq!(res.is_err(), false);

		let res = res.unwrap();
		assert_eq!(res, true);
		assert_eq!(value_read, [5, 5, 5]);
	}

	#[test]
	fn test_static_hash_advanced() {
		use rand::Rng;
		let mut hashtable = StaticHash::new(100000, 16, 32, 0.9).unwrap();
		let mut rng = rand::thread_rng();
		let mut kvec: Vec<[u8; 16]> = Vec::new();
		let mut vvec: Vec<[u8; 32]> = Vec::new();
		let mut vreadvec: Vec<[u8; 32]> = Vec::new();

		for i in 0..76000 {
			let k1: [u8; 16] = rng.gen();
			let v1: [u8; 32] = rng.gen();
			let ret = hashtable.put(&k1, &v1);
			assert_eq!(ret.is_err(), false);
			kvec.insert(i, k1);
			vvec.insert(i, v1);
		}

		// remove several entries

		let res = hashtable.remove(&kvec[45]);
		assert_eq!(res.is_err(), false);
		assert_eq!(res.unwrap(), true);
		kvec.remove(45);
		vvec.remove(45);

		let res = hashtable.remove(&kvec[13]);
		assert_eq!(res.is_err(), false);
		assert_eq!(res.unwrap(), true);
		kvec.remove(13);
		vvec.remove(13);

		let res = hashtable.remove(&kvec[37]);
		assert_eq!(res.is_err(), false);
		assert_eq!(res.unwrap(), true);
		kvec.remove(37);
		vvec.remove(37);

		for i in 0..75997 {
			let mut vread = [0 as u8; 32];
			let res = hashtable.get(&kvec[i], &mut vread);
			assert_eq!(res.is_err(), false);
			vreadvec.insert(i, vread);
		}
		assert_eq!(vreadvec, vvec);
	}

	#[test]
	fn test_static_hash_stats() {
		use rand::Rng;
		let mut rng = rand::thread_rng();
		let mut hashtable = StaticHash::new(100000, 16, 32, 0.9).unwrap();
		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();
		let ret = hashtable.put(&k1, &v1);
		assert_eq!(ret.is_ok(), true);

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();
		let ret = hashtable.put(&k2, &v2);
		assert_eq!(ret.is_ok(), true);

		let k3: [u8; 16] = rng.gen();
		let v3: [u8; 32] = rng.gen();
		let ret = hashtable.put(&k3, &v3);
		assert_eq!(ret.is_ok(), true);

		let k4: [u8; 16] = rng.gen();
		let v4: [u8; 32] = rng.gen();
		let ret = hashtable.put(&k4, &v4);
		assert_eq!(ret.is_ok(), true);

		let res = hashtable.remove(&k2);
		assert_eq!(res.unwrap(), true);
		assert_eq!(hashtable.stats.cur_elements, 3);
		assert_eq!(hashtable.stats.max_elements, 4);
	}

	#[test]
	fn test_static_hash_load_factor() {
		use rand::Rng;
		let mut rng = rand::thread_rng();

		let mut hashtable = StaticHash::new(9, 16, 32, 0.9).unwrap();

		for _ in 0..7 {
			let k: [u8; 16] = rng.gen();
			let v: [u8; 32] = rng.gen();
			let res = hashtable.put(&k, &v);
			assert_eq!(res.is_ok(), true);
		}

		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();

		let res = hashtable.put(&k1, &v1);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k2, &v2);
		assert_eq!(res.is_ok(), false);

		let res = hashtable.remove(&k1);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = hashtable.put(&k2, &v2);
		assert_eq!(res.is_ok(), true);
	}

	#[test]
	fn test_static_hash_iterator() {
		use rand::Rng;
		let mut rng = rand::thread_rng();

		let mut hashtable = StaticHash::new(9, 16, 32, 0.9).unwrap();

		let k1: [u8; 16] = rng.gen();
		let v1: [u8; 32] = rng.gen();

		let k2: [u8; 16] = rng.gen();
		let v2: [u8; 32] = rng.gen();

		let k3: [u8; 16] = rng.gen();
		let v3: [u8; 32] = rng.gen();

		let k4: [u8; 16] = rng.gen();
		let v4: [u8; 32] = rng.gen();

		let k5: [u8; 16] = rng.gen();
		let v5: [u8; 32] = rng.gen();

		let res = hashtable.put(&k1, &v1);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k2, &v2);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k3, &v3);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k4, &v4);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.put(&k5, &v5);
		assert_eq!(res.is_ok(), true);

		let res = hashtable.remove(&k2);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let mut input = Vec::new();
		input.insert(0, k1);
		input.insert(1, k3);
		input.insert(2, k4);
		input.insert(3, k5);
		input.sort();
		let mut vinput = Vec::new();
		vinput.insert(0, v1);
		vinput.insert(1, v3);
		vinput.insert(2, v4);
		vinput.insert(3, v5);
		vinput.sort();

		let iterator = StaticHashIterator::new(hashtable);
		assert_eq!(iterator.is_err(), false);
		let mut iterator = iterator.unwrap();

		let mut k1: [u8; 16] = rng.gen();
		let mut k2: [u8; 16] = rng.gen();
		let mut k3: [u8; 16] = rng.gen();
		let mut k4: [u8; 16] = rng.gen();
		let mut k5: [u8; 16] = rng.gen();

		let mut v1: [u8; 32] = rng.gen();
		let mut v2: [u8; 32] = rng.gen();
		let mut v3: [u8; 32] = rng.gen();
		let mut v4: [u8; 32] = rng.gen();
		let mut v5: [u8; 32] = rng.gen();

		let res = iterator.next(&mut k1, &mut v1);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k2, &mut v2);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k3, &mut v3);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k4, &mut v4);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), true);

		let res = iterator.next(&mut k5, &mut v5);
		assert_eq!(res.is_ok(), true);
		assert_eq!(res.unwrap(), false);

		let mut output = Vec::new();
		output.insert(0, k1);
		output.insert(0, k2);
		output.insert(0, k3);
		output.insert(0, k4);
		output.sort();

		let mut voutput = Vec::new();
		voutput.insert(0, v1);
		voutput.insert(0, v2);
		voutput.insert(0, v3);
		voutput.insert(0, v4);
		voutput.sort();

		assert_eq!(input, output);
		assert_eq!(vinput, voutput);
	}
}
