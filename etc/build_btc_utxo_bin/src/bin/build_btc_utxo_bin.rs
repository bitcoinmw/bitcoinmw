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

extern crate byteorder;

use byteorder::{LittleEndian, WriteBytesExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::mem;

use structopt::StructOpt;

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

const DIGITS58: [char; 58] = [
	'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
	'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e',
	'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
	'z',
];

fn from_base58(encoded: &str, size: usize) -> Result<Vec<u8>, String> {
	let mut res: Vec<u8> = vec![0; size];
	for base58_value in encoded.chars() {
		let mut value: u32 = match DIGITS58.iter().position(|x| *x == base58_value) {
			Some(x) => x as u32,
			None => return Err(String::from("Invalid character found in encoded string.")),
		};
		for result_index in (0..size).rev() {
			value += 58 * res[result_index] as u32;
			res[result_index] = (value % 256) as u8;
			value /= 256;
		}
	}
	Ok(res)
}

const DIGITS32: [char; 32] = [
	'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
	'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

fn from_base32(encoded: &str, size: usize) -> Result<Vec<u8>, String> {
	let encoded = &encoded[4..];
	let mut res: Vec<u8> = vec![0; size];

	for base32_value in encoded.chars() {
		let mut value: u32 = match DIGITS32.iter().position(|x| *x == base32_value) {
			Some(x) => x as u32,
			None => return Err(String::from("Invalid character found in encoded string.")),
		};
		for result_index in (0..size).rev() {
			value += 32 * res[result_index] as u32;
			res[result_index] = (value % 256) as u8;
			value /= 256;
		}
	}
	Ok(res)
}

fn encode_value(value: f64) -> Vec<u8> {
	// convert to sats
	let nval: f64 = value * 100_000_000 as f64;
	let nval: u64 = nval.round() as u64;

	let mut ret = [0u8; mem::size_of::<u64>()];

	ret.as_mut()
		.write_u64::<LittleEndian>(nval)
		.expect("Unable to write");

	return ret.to_vec();
}

fn encode_addr(address: String) -> Vec<u8> {
	if address.starts_with("1") {
		return from_base58(&address, 25).unwrap();
	} else if address.starts_with("3") {
		return from_base58(&address, 25).unwrap();
	} else if address.starts_with("b") {
		return from_base32(&address, 25).unwrap();
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
		buffer.write_all(&encoded_addr[1..])?;
		let encoded_value = encode_value(*value);
		buffer.write_all(&encoded_value)?;
	}

	buffer.flush()?;

	Ok(())
}
