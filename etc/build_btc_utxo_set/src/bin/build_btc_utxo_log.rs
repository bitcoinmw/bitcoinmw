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

extern crate rand;
extern crate secp256k1;

use std::io::Write;
use std::fs::OpenOptions;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value::Null;
use serde_json::{Error, Value};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct BtcBlock {
	tx: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct BtcTransaction {
	vin: Option<Value>,
	vout: Option<Value>,
}

#[derive(Debug)]
struct Output {
	value: f64,
	address: String,
}

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Cli {
	rpcuser: String,
	rpcpassword: String,
	rpcconnect: String,
	rpcport: String,
	outfile: String,
	maxheight: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Cli::from_args();
	let rpcuser = args.rpcuser;
	let rpcpassword = args.rpcpassword;
	let rpcconnect = args.rpcconnect;
	let rpcport = args.rpcport;
	let outfile = args.outfile;
	let max_height = args.maxheight;

	let network = Network::Bitcoin;

	let _ = std::fs::remove_file(outfile.clone());
	let mut file = OpenOptions::new().write(true).create(true).open(outfile)?;

	for i in 1..max_height {
		let mut cmd = Command::new("bitcoin-cli")
			.arg("-rpcuser=".to_owned() + &rpcuser)
			.arg("-rpcpassword=".to_owned() + &rpcpassword)
			.arg("-rpcconnect=".to_owned() + &rpcconnect)
			.arg("-rpcport=".to_owned() + &rpcport)
			.arg("getblockhash")
			.arg(format!("{}", i))
			.stdout(Stdio::piped())
			.spawn()
			.expect("bitcoin-cli command failed to start");


		let stdout = cmd.stdout.as_mut().unwrap();

		let stdout_reader = BufReader::new(stdout);
		let stdout_lines = stdout_reader.lines();
		std::thread::sleep(std::time::Duration::from_millis(1));

		for line in stdout_lines {
			let line = line.unwrap();
			println!("processing block {}: {:?}", i, line);
			let mut cmd = Command::new("bitcoin-cli")
				.arg("-rpcuser=".to_owned() + &rpcuser)
				.arg("-rpcpassword=".to_owned() + &rpcpassword)
				.arg("-rpcconnect=".to_owned() + &rpcconnect)
				.arg("-rpcport=".to_owned() + &rpcport)
				.arg("getblock")
				.arg(line)
				.arg("1")
				.stdout(Stdio::piped())
				.spawn()
				.expect("bitcoin-cli command failed to start");

			let stdout = cmd.stdout.as_mut().unwrap();
			let u: Result<BtcBlock, Error> = serde_json::from_reader(stdout);
			let u = u.unwrap();
			let arr = u.tx.unwrap();
			let mut index = 0;

			std::thread::sleep(std::time::Duration::from_millis(1));

			loop {
				if arr[index] == Null {
					break;
				}
				let tx_id = &arr[index];
				let mut cmd = Command::new("bitcoin-cli")
					.arg("-rpcuser=".to_owned() + &rpcuser)
					.arg("-rpcpassword=".to_owned() + &rpcpassword)
					.arg("-rpcconnect=".to_owned() + &rpcconnect)
					.arg("-rpcport=".to_owned() + &rpcport)
					.arg("getrawtransaction")
					.arg(tx_id.as_str().unwrap())
					.arg("1")
					.stdout(Stdio::piped())
					.spawn()
					.expect("bitcoin-cli command failed to start");

				let stdout = cmd.stdout.as_mut().unwrap();
				let u: Result<BtcTransaction, Error> = serde_json::from_reader(stdout);
				let u = u.unwrap();
				let arr_in = u.vin.unwrap();
				let arr_out = u.vout.unwrap();
				std::thread::sleep(std::time::Duration::from_millis(1));

				let mut index_in = 0;
				let mut index_out = 0;

				loop {
					if arr_in[index_in] == Null {
						break;
					}
					let vin = &arr_in[index_in];
					let tx_id = vin.get("txid");
					let index = vin.get("vout");
					if tx_id.is_some() && index.is_some() {
						let tx_id = tx_id.unwrap().as_str().unwrap();
						let index = index.unwrap();
    						write!(file, "rem = {} {}", tx_id, index)?;
					}
					index_in = index_in + 1;
				}

				let tx_id = tx_id.as_str().unwrap();
				loop {
					if arr_out[index_out] == Null {
						break;
					}
					let vout = &arr_out[index_out];
					let script_pub_key = vout.get("scriptPubKey");
					let value = vout.get("value");
					let n = vout.get("n");
					if script_pub_key.is_some() && value.is_some() && n.is_some() {
						let value = value.unwrap().as_f64().unwrap();
						let n = n.unwrap();
						let script_pub_key = script_pub_key.unwrap();
						let addresses = script_pub_key.get("addresses");
						if addresses.is_some() {
							let addresses = addresses.unwrap();
							for address in addresses.as_array() {
								for x in 0..address.len() {
									let address = address[x].as_str().unwrap().to_string();
									write!(file, "val = {} {} {} {}\n",address,tx_id,n,value)?;
								}
							}
						} else {
							let asm = script_pub_key.get("asm");
							if asm.is_some() {
								let asm = asm.unwrap();
								let split = asm.as_str().unwrap().split(" ");
								let vec: Vec<&str> = split.collect();
								let hex = hex::decode(vec[0]).unwrap();
								let public_key = bitcoin::PublicKey::from_slice(&hex).unwrap();
								let address = Address::p2pkh(&public_key, network).to_string();
								write!(file, "val = {} {} {} {}\n",address,tx_id,n,value)?;
							}
						}
					}

					index_out = index_out + 1;
				}

				index = index + 1;
			}
		}
	}

	Ok(())
}
