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

use byte_tools::copy;
use byteorder::{LittleEndian, ReadBytesExt};
use std::convert::TryInto;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use structopt::StructOpt;
use util::print_util::format_f64;
use util::print_util::print;
use util::FLAG_BECH32_ADDRESS;
use util::FLAG_LEGACY_ADDRESS;
use util::FLAG_P2SH_ADDRESS;

use failure::{Context, Fail};

/// Error definition
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Index out of bounds")]
	IndexOutOfBounds,
	/// IO Error
	#[fail(display = "IO Error: {}", _0)]
	IOError(String),
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IOError(error.to_string())),
		}
	}
}

#[derive(StructOpt, Debug)]
struct Cli {
	gen_bin: String,
}

// read sats from a byte array resetting any flags
fn read_sats(bytes: &[u8]) -> Result<u64, Error> {
	let mut ret = read_num(bytes)?;
	ret &= !FLAG_LEGACY_ADDRESS;
	ret &= !FLAG_P2SH_ADDRESS;
	ret &= !FLAG_BECH32_ADDRESS;
	Ok(ret)
}

// read the raw number from a 6 byte little endian byte array
fn read_num(bytes: &[u8]) -> Result<u64, Error> {
	let mut vec = bytes.to_vec();
	vec.append(&mut vec![0x0, 0x0]);
	let num = Cursor::new(vec).read_u64::<LittleEndian>()?;
	Ok(num)
}

fn get_data_for_index(
	index: u32,
	short_count: u32,
	long_count: u32,
	v1plus_count: u32,
	data: &Vec<u8>,
) -> Result<Vec<u8>, Error> {
	let mut ret = Vec::new();
	if index < short_count {
		// it's a short index
		let offset = index * 26 + 16;
		for i in offset..offset + 26 {
			ret.push(data[i as usize]);
		}
	} else if index < (short_count + long_count) {
		// it's a long index
		let offset = short_count * 26 + (index - short_count) * 38 + 16;
		for i in offset..offset + 38 {
			ret.push(data[i as usize]);
		}
	} else if index < (short_count + long_count + v1plus_count) {
		let offset =
			short_count * 26 + long_count * 38 + (index - (short_count + long_count)) * 80 + 16;
		for i in offset..offset + 80 {
			ret.push(data[i as usize]);
		}
	} else {
		// out of bounds
		return Err(ErrorKind::IndexOutOfBounds.into());
	}

	Ok(ret)
}

fn main() -> Result<(), Error> {
	let args = Cli::from_args();
	let gen_bin = args.gen_bin;

	let mut file = File::open(gen_bin.to_string())?;
	let len = std::fs::metadata(gen_bin.to_string())?.len();
	let mut data = Vec::new();
	data.resize(len.try_into().unwrap(), 0);
	file.read(&mut data)?;

	let mut tmp = [0 as u8; 4];

	copy(&data[0..4], &mut tmp);
	let short_count = Cursor::new(tmp).read_u32::<LittleEndian>()?;

	copy(&data[4..8], &mut tmp);
	let long_count = Cursor::new(tmp).read_u32::<LittleEndian>()?;

	copy(&data[8..12], &mut tmp);
	let v1plus_count = Cursor::new(tmp).read_u32::<LittleEndian>()?;

	print(format!("binary=\"{}\"", gen_bin));
	print(format!("short_count={}", short_count));
	print(format!("long_count={}", long_count));
	print(format!("v1plus_count={}", v1plus_count));
	println!("----------------------------------------------------------------");

	let mut sat_sum = 0;
	let mut count = 0;

	for i in 0..short_count + long_count + v1plus_count {
		let d = get_data_for_index(i, short_count, long_count, v1plus_count, &data)?;

		let len = d.len();
		let sats = read_sats(&d[len - 6..])?;
		sat_sum += sats;
		if i % 100_000 == 0 {
			print(format!(
				"i={},btc={}",
				i,
				format_f64(sat_sum as f64 / 100_000_000 as f64)
			));
		}
		count += 1;
	}
	println!("----------------------------------------------------------------");
	print(format!(
		"sum={},addresses={}",
		format_f64(sat_sum as f64 / 100_000_000 as f64),
		count,
	));

	Ok(())
}
