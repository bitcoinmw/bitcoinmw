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

use std::io::Write;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Cli::from_args();
	let infile = args.infile;
	let outfile = args.outfile;

	let _ = std::fs::remove_file(outfile.clone());
	let mut fout = OpenOptions::new().write(true).create(true).open(outfile)?;

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
				map.insert(key,
					OutputValue {address: format!("{}", split[1]), value: nval + cur});
			} else {
				map.insert(key,
					OutputValue {address: format!("{}", split[1]), value: split[4].parse().unwrap()});
			}
		} else if split[0] == "rem" {
			let key = format!("{}-{}", split[1], split[2]);
			map.remove(&key);
		}
	}

	for (_, value) in &map {
		write!(fout, "{}: {}\n", value.address, value.value)?;
	}

	Ok(())
}
