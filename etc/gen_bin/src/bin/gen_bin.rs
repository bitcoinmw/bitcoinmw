// Copyright 2020 The BitcoinMW Developers
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

//! Main for building btc utxo log at specific block height

extern crate bech32;
extern crate byteorder;
extern crate rust_base58;

use byte_tools::copy;
use byteorder::{LittleEndian, ReadBytesExt};
use num_format::{Locale, ToFormattedString};
use std::fs::remove_file;
use std::fs::File;
use std::io::BufWriter;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, BufReader};
use structopt::StructOpt;
use util::encode_addr;
use util::print_util::format_f64;
use util::print_util::print;
use util::static_hash::StaticHash;
use util::static_hash::StaticHashIterator;
use util::FLAG_BECH32_ADDRESS;
use util::FLAG_BECH32_V1_PLUS_ADDRESS;
use util::FLAG_LEGACY_ADDRESS;
use util::FLAG_P2SH_ADDRESS;

#[derive(StructOpt, Debug)]
struct Cli {
	infile: String,
	outfile: String,
}

#[derive(Debug)]
struct OutputValue {
	address: String,
	value: f64,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SortableValue {
	address: String,
	address_enc: Vec<u8>,
	value_enc: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Cli::from_args();
	let infile = args.infile;
	let outfile = args.outfile;
	let mut reg_count = 0;

	let _ = std::fs::remove_file(outfile.clone());

	let infile = File::open(infile)?;
	let reader = BufReader::new(infile);

	// must scope the hashtable since it uses a lot of memory.
	{
		print("Instantiating static_hash.".to_string());
		let mut static_hash = StaticHash::new(200_000_000, 34, 38, 0.9).unwrap();

		// separate hashmap for these
		let mut bech32_v1_plus_hash_map = StaticHash::new(20_000, 34, 80, 0.9).unwrap();
		print("Instantiation of static_hash complete. Loading txs.".to_string());
		let mut count = 0;
		for line in reader.lines() {
			let last_height;
			count += 1;
			let line = line?;
			let split: Vec<&str> = line.split(" ").collect();
			if split[0] == "add" {
				last_height = split[5];
				let key1 = hex::decode(split[2])?;
				let key_u16 = split[3].parse::<u16>().unwrap().to_be_bytes();
				let key1 = [&key1[..], &key_u16].concat();
				let mut value = [0 as u8; 38];
				let mut value_l = [0 as u8; 80];
				let found = static_hash.get(&key1, &mut value).unwrap();

				// if we find any duplicates other than the two known ones, we exit.
				if found
					&& split[2]
						!= "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"
					&& split[2]
						!= "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"
				{
					print(format!(
						"FATAL: Duplicate found [{}-{}]!",
						split[2], split[3]
					));
					std::process::exit(-1);
				} else {
					let addr = split[1].to_string();
					if addr.len() > 12 {
						let addr_encoded = encode_addr(split[1].to_string());
						if addr_encoded.is_err() {
							print(format!(
								"Warning: unencodable address: {} [generated error: {:?}",
								split[1], addr_encoded
							));
							// we continue in this case. Try to resolve all of these.
							continue;
						}
						let addr_encoded = addr_encoded.unwrap();

						if addr_encoded.len() == 74 {
							copy(&addr_encoded, &mut value_l);
						} else {
							copy(&addr_encoded, &mut value);
						}

						// we hard code the two duplicate coinbases to 100 BTC.
						let mut amount = if
							split[2] == "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468" ||
							split[2] == "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599" {
							100 * 100_000_000 as u64
						} else {
							(split[4].parse::<f64>().unwrap() * 100_000_000 as f64) as u64
						};
						let mut version: Option<char> = None;
						let flag = match split[1].chars().next() {
							Some('1') => FLAG_LEGACY_ADDRESS,
							Some('3') => FLAG_P2SH_ADDRESS,
							Some('b') => {
								let mut chars = split[1].chars();
								chars.next();
								chars.next();
								chars.next();
								version = chars.next();
								match version {
									Some('q') => FLAG_BECH32_ADDRESS,
									_ => FLAG_BECH32_V1_PLUS_ADDRESS,
								}
							}
							_ => FLAG_BECH32_ADDRESS,
						};
						amount |= flag;

						let bytes = amount.to_le_bytes();
						let bytes = &bytes[0..6];

						if flag == FLAG_BECH32_V1_PLUS_ADDRESS {
							// v1 plus address, don't add it to the regular hash,
							// special hash
							copy(&bytes, &mut value_l[74..]);
							value_l[72] = match version.unwrap() {
								'p' => 1,
								'z' => 2,
								_ => {
									// none of these, so error for now
									print(format!("FATAL: unknown bech32 address {}", split[1]));
									std::process::exit(-1);
								}
							};
							value_l[73] = split[1].len() as u8;
							let res = bech32_v1_plus_hash_map.put(&key1, &value_l);
							if res.is_err() {
								print(format!("FATAL: {:?}", res));
								std::process::exit(-1);
							}
						} else {
							// regular address
							copy(&bytes, &mut value[32..]);
							let res = static_hash.put(&key1, &value);
							if res.is_err() {
								print(format!("FATAL: {:?}", res));
								std::process::exit(-1);
							}
						}
					} else if addr == "none" {
						// from a script
						for i in 0..value.len() {
							value[i] = 0;
						}
						let amount = (split[4].parse::<f64>().unwrap() * 100_000_000 as f64) as u64
							| FLAG_LEGACY_ADDRESS;
						let bytes = amount.to_le_bytes();
						let bytes = &bytes[0..6];
						copy(&bytes, &mut value[32..]);
						let res = static_hash.put(&key1, &value);
						if res.is_err() {
							print(format!("FATAL: {:?}", res));
							std::process::exit(-1);
						}
					} else {
						print(format!("FATAL: {}", addr));
						std::process::exit(-1);
					}
				}
			} else if split[0] == "rem" {
				last_height = split[3];
				let key1 = hex::decode(split[1])?;
				let key_u16 = split[2].parse::<u16>().unwrap().to_be_bytes();
				let key1 = [&key1[..], &key_u16].concat();
				let ret = static_hash.remove(&key1).unwrap();
				if !ret {
					// try to remove from our other hashtable
					let ret = bech32_v1_plus_hash_map.remove(&key1).unwrap();
					if !ret {
						print(format!(
							"FATAL: Error removing txid={},vout={} {:?}",
							split[1], split[2], ret
						));
						std::process::exit(-1);
					}
				}
			} else {
				// not supposed to happen. corrupt log file?
				last_height = "unknown";
			}
			if count % 1000000 == 0 {
				let last_height = last_height.parse::<u32>().unwrap();
				let last_height = last_height.to_formatted_string(&Locale::en);
				print(format!(
					"max_load_factor={},cur_load_factor={},visits_per_call={},height={}",
					format_f64(
						static_hash.stats.max_elements as f64 / static_hash.max_entries as f64
					),
					format_f64(
						static_hash.stats.cur_elements as f64 / static_hash.max_entries as f64
					),
					format_f64(
						static_hash.stats.total_node_reads as f64
							/ static_hash.stats.access_count as f64
					),
					last_height,
				));
			}
		}

		print(format!("Txs loaded. Now writing to temp file."));

		let mut iterator = StaticHashIterator::new(static_hash).unwrap();
		// remove temp file if it exists
		let _ = remove_file("/tmp/gen_bin.tmp"); // if it exists remove it.
		let mut buffer = BufWriter::new(File::create("/tmp/gen_bin.tmp")?);
		let mut key = [0 as u8; 34];
		let mut value = [0 as u8; 38];
		let empty_bytes = [0 as u8; 42];

		loop {
			let res = iterator.next(&mut key, &mut value).unwrap();
			if !res {
				break;
			}
			buffer.write_all(&key)?;
			buffer.write_all(&value)?;
			buffer.write_all(&empty_bytes)?;
			reg_count += 1;
		}
		// now iterate over the v1plus hash

		let mut iterator = StaticHashIterator::new(bech32_v1_plus_hash_map).unwrap();
		let mut value = [0 as u8; 80];
		loop {
			let res = iterator.next(&mut key, &mut value).unwrap();
			if !res {
				break;
			}
			buffer.write_all(&key)?;
			buffer.write_all(&value)?;
		}

		buffer.flush()?;

		print(format!("Temp file creation complete."));
	}

	print(format!("Sums being calculated."));

	let mut addr_values_small = Vec::new();
	let mut addr_values = Vec::new();
	let mut addr_values_v1_plus = Vec::new();
	// now that the hashtable is out of scope read back the file and put data into the new hashtable.
	{
		let mut buffer = BufReader::new(File::open("/tmp/gen_bin.tmp")?);
		let mut static_hash = StaticHash::new(200_000_000, 32, 8, 0.9).unwrap();
		let mut bech32_v1_plus_hash_map = StaticHash::new(20_000, 74, 8, 0.9).unwrap();

		let mut key = [0 as u8; 34];
		let mut value = [0 as u8; 80];
		let mut count = 0;
		let mut itt_count = 0;
		loop {
			let mut rlen = buffer.read(&mut key)?;
			if rlen == 0 {
				break;
			}
			loop {
				if rlen == 34 {
					break;
				}

				rlen += buffer.read(&mut key[rlen..])?;
			}
			let mut rlen = buffer.read(&mut value)?;
			if rlen == 0 {
				break;
			}
			loop {
				if rlen == 80 {
					break;
				}
				rlen += buffer.read(&mut value[rlen..])?;
			}

			if itt_count < reg_count {
				let amt_vec = &mut value[32..38].to_vec();
				amt_vec.insert(6, 0 as u8);
				amt_vec.insert(7, 0 as u8);
				let mut rdr = Cursor::new(amt_vec.clone());
				let mut amount = rdr.read_u64::<LittleEndian>().unwrap();
				let nkey = &value[0..32];
				let mut nval = [0 as u8; 8];
				let res = static_hash.get(&nkey, &mut nval).unwrap();

				if res {
					let mut rdr = Cursor::new(nval.to_vec());
					let prev_amt = rdr.read_u64::<LittleEndian>().unwrap();
					// set flags off for all but one value
					amount = amount & !FLAG_LEGACY_ADDRESS;
					amount = amount & !FLAG_P2SH_ADDRESS;
					amount = amount & !FLAG_BECH32_ADDRESS;
					amount += prev_amt;
				} else {
					count += 1;
					if count % 100000 == 0 {
						let count_display = count.to_formatted_string(&Locale::en);
						print(format!("Discovered {} addresses.", count_display));
					}
				}

				nval = amount.to_le_bytes();
				static_hash.put(&nkey, &nval).unwrap();
			} else {
				let amt_vec = &mut value[74..].to_vec();
				amt_vec.insert(6, 0 as u8);
				amt_vec.insert(7, 0 as u8);
				let mut rdr = Cursor::new(amt_vec.clone());
				let mut amount = rdr.read_u64::<LittleEndian>().unwrap();
				let nkey = &value[0..74];
				let mut nval = [0 as u8; 8];
				let res = bech32_v1_plus_hash_map.get(&nkey, &mut nval).unwrap();

				if res {
					let mut rdr = Cursor::new(nval.to_vec());
					let prev_amt = rdr.read_u64::<LittleEndian>().unwrap();
					// set flags off for all but one value
					amount = amount & !FLAG_LEGACY_ADDRESS;
					amount = amount & !FLAG_P2SH_ADDRESS;
					amount = amount & !FLAG_BECH32_ADDRESS;
					amount += prev_amt;
				} else {
					count += 1;
					if count % 100000 == 0 {
						let count_display = count.to_formatted_string(&Locale::en);
						print(format!("Discovered {} addresses.", count_display));
					}
				}

				nval = amount.to_le_bytes();
				bech32_v1_plus_hash_map.put(&nkey, &nval).unwrap();
			}
			itt_count += 1;
		}

		print(format!("Sums completely calculated."));
		let count_display = count.to_formatted_string(&Locale::en);
		print(format!("Discovered {} addresses in total.", count_display));

		let mut iterator = StaticHashIterator::new(static_hash).unwrap();
		let mut key = [0 as u8; 32];
		let mut value = [0 as u8; 8];
		let mut key_v1_plus = [0 as u8; 74];
		let mut combined_v1_plus = [0 as u8; 80];
		let mut combined = [0 as u8; 38];
		let mut combined_small = [0 as u8; 26];
		loop {
			let res = iterator.next(&mut key, &mut value).unwrap();
			if !res {
				break;
			}

			if key[31] == 0
				&& key[30] == 0 && key[29] == 0
				&& key[28] == 0 && key[27] == 0
				&& key[26] == 0 && key[25] == 0
			{
				// small address
				copy(&key[0..20], &mut combined_small);
				copy(&value[0..6], &mut combined_small[20..]);
				addr_values_small.push(combined_small);
			} else {
				// big address
				copy(&key, &mut combined);
				copy(&value[0..6], &mut combined[32..]);
				addr_values.push(combined);
			}
		}

		let mut iterator = StaticHashIterator::new(bech32_v1_plus_hash_map).unwrap();
		loop {
			let res = iterator.next(&mut key_v1_plus, &mut value).unwrap();
			if !res {
				break;
			}
			copy(&key_v1_plus, &mut combined_v1_plus);
			copy(&value[0..6], &mut combined_v1_plus[74..]);
			addr_values_v1_plus.push(combined_v1_plus);
		}

		drop(buffer);
	}

	let len = addr_values_v1_plus.len();
	let len = len.to_formatted_string(&Locale::en);

	print(format!("Sorting bech32 v1plus addresses ({})", len));
	addr_values_v1_plus.sort();
	print("Sorting bech32 v1plus addresses complete.".to_string());

	let len = addr_values.len();
	let len = len.to_formatted_string(&Locale::en);

	print(format!("Sorting long addresses ({})", len));
	addr_values.sort();
	print("Sorting long addresses complete.".to_string());

	let len = addr_values_small.len();
	let len = len.to_formatted_string(&Locale::en);

	print(format!("Sorting short addresses ({})", len));
	addr_values_small.sort();
	print("Sorting short addresses complete. Writing binary to disk.".to_string());

	let mut buffer = BufWriter::new(File::create(outfile)?);

	buffer.write_all(&(addr_values_small.len() as u32).to_le_bytes())?;
	buffer.write_all(&(addr_values.len() as u32).to_le_bytes())?;
	buffer.write_all(&(addr_values_v1_plus.len() as u32).to_le_bytes())?;
	buffer.write_all(&(0 as u32).to_le_bytes())?; // place holder for legacy scripts

	for addr in &addr_values_small {
		buffer.write_all(addr)?;
	}
	for addr in &addr_values {
		buffer.write_all(addr)?;
	}
	for addr in &addr_values_v1_plus {
		buffer.write_all(addr)?;
	}

	// remove temp file
	remove_file("/tmp/gen_bin.tmp")?;

	print("Binary comletely written to disk. Thank you.".to_string());

	Ok(())
}
