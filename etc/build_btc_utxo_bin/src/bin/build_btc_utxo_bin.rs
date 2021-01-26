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

use bech32::u5;
use bech32::FromBase32;
use byteorder::{LittleEndian, WriteBytesExt};
use rust_base58::FromBase58;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::mem;
use structopt::StructOpt;

const FLAG_LEGACY_ADDRESS: u64 = 0x8000000000000000;
const FLAG_P2SH_ADDRESS: u64 = 0x4000000000000000;
const FLAG_BECH32_ADDRESS: u64 = 0x2000000000000000;

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

fn from_base58(encoded: &str) -> Result<Vec<u8>, String> {
	let mut ret = encoded.from_base58().unwrap();
	ret.remove(0);
	Ok(ret)
}

fn from_base32(encoded: &str) -> Result<Vec<u8>, String> {
	let mut padded = [u5::try_from_u8(0).unwrap(); 32];
	let (_, data) = bech32::decode(&encoded).unwrap();
	padded[..32].copy_from_slice(&data[1..]);
	let mut ret = Vec::<u8>::from_base32(&padded).unwrap();
	ret.append(&mut vec![0 as u8, 0 as u8, 0 as u8, 0 as u8]);
	Ok(ret)
}

fn encode_value(value: f64, flag: u64) -> Vec<u8> {
	// convert to sats
	let nval: f64 = value * 100_000_000 as f64;
	let nval: u64 = (nval.round() as u64) | flag;

	let mut ret = [0u8; mem::size_of::<u64>()];

	ret.as_mut()
		.write_u64::<LittleEndian>(nval)
		.expect("Unable to write");

	return ret.to_vec();
}

fn encode_addr(address: String) -> Vec<u8> {
	if address.starts_with("1") {
		return from_base58(&address).unwrap();
	} else if address.starts_with("3") {
		return from_base58(&address).unwrap();
	} else if address.starts_with("b") {
		return from_base32(&address).unwrap();
	}
	println!("WARNING: Unknown address type: {}", address);
	return vec![0; 1];
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Cli::from_args();
	let infile = args.infile;
	let outfile = args.outfile;

	let _ = std::fs::remove_file(outfile.clone());

	let infile = File::open(infile)?;
	let reader = BufReader::new(infile);

	let mut map: HashMap<String, OutputValue> = HashMap::new();

	for line in reader.lines() {
		let line = line?;
		let split: Vec<&str> = line.split(" ").collect();
		if split[0] == "add" {
			let key = format!("{}-{}", split[2], split[3]);
			let found = map.get(&key);

			if found.is_some() {
				let cur = found.unwrap().value;
				let nval = split[4].parse::<f64>().unwrap();
				map.remove(&key);
				map.insert(
					key,
					OutputValue {
						address: format!("{}", split[1]),
						value: nval + cur,
					},
				);
			} else {
				map.insert(
					key,
					OutputValue {
						address: format!("{}", split[1]),
						value: split[4].parse().unwrap(),
					},
				);
			}
		} else if split[0] == "rem" {
			let key = format!("{}-{}", split[1], split[2]);
			map.remove(&key);
		}
	}

	let mut addr_map: HashMap<String, f64> = HashMap::new();
	for (_, value) in &map {
		let found = addr_map.get(&value.address);
		if found.is_some() {
			let cur_val = found.unwrap().clone();
			addr_map.insert(value.address.clone(), value.value + cur_val);
		} else {
			addr_map.insert(value.address.clone(), value.value);
		}
	}

	let mut buffer = BufWriter::new(File::create(outfile)?);

	for (key, value) in &addr_map {
		let encoded_addr = encode_addr(key.to_string());
		buffer.write_all(&encoded_addr)?;

		let flag = match key.chars().next() {
			Some('1') => FLAG_LEGACY_ADDRESS,
			Some('3') => FLAG_P2SH_ADDRESS,
			Some('b') => FLAG_BECH32_ADDRESS,
			_ => FLAG_BECH32_ADDRESS,
		};

		let encoded_value = encode_value(*value, flag);
		buffer.write_all(&encoded_value)?;
	}

	buffer.flush()?;

	Ok(())
}
