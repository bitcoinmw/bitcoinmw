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

//! Main for building btc utxo set at specific block height

extern crate rand;
extern crate secp256k1;

use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value::Null;
use serde_json::{Error, Value};
use std::collections::HashMap;
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
}

fn main() {
	let args = Cli::from_args();
	let rpcuser = args.rpcuser;
	let rpcpassword = args.rpcpassword;
	let rpcconnect = args.rpcconnect;
	let rpcport = args.rpcport;
	let network = Network::Bitcoin;

	// Generate random key pair
	//let hex = hex::decode("0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee").unwrap();
	//let public_key = bitcoin::PublicKey::from_slice(&hex).unwrap();

	// Generate pay-to-pubkey address
	//let address = Address::p2pkh(&public_key, network);
	//println!("addr = {}", address);

	let mut utxo_map: HashMap<String, Output> = HashMap::new();

	for i in 1..650000 {
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

		for line in stdout_lines {
			println!("block {}: {:?}", i, line);
			let mut cmd = Command::new("bitcoin-cli")
				.arg("-rpcuser=".to_owned() + &rpcuser)
				.arg("-rpcpassword=".to_owned() + &rpcpassword)
				.arg("-rpcconnect=".to_owned() + &rpcconnect)
				.arg("-rpcport=".to_owned() + &rpcport)
				.arg("getblock")
				.arg(line.unwrap())
				.arg("1")
				.stdout(Stdio::piped())
				.spawn()
				.expect("bitcoin-cli command failed to start");

			let stdout = cmd.stdout.as_mut().unwrap();
			let u: Result<BtcBlock, Error> = serde_json::from_reader(stdout);
			let u = u.unwrap();
			let arr = u.tx.unwrap();
			let mut index = 0;
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
						let fmt = format!("{}-{}", tx_id, index);
						utxo_map.remove(&fmt);
						//println!("rem = {}", fmt);
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
							let fmt = format!("{}-{}", tx_id, n);
							let addresses = addresses.unwrap();
							for address in addresses.as_array() {
								for x in 0..address.len() {
									let address = address[x].as_str().unwrap().to_string();
									utxo_map.insert(
										fmt.clone(),
										Output {
											value: value.clone(),
											address: address.clone(),
										},
									);
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
								let fmt = format!("{}-{}", tx_id, n);
								utxo_map.insert(
									fmt.clone(),
									Output {
										value: value.clone(),
										address: address.clone(),
									},
								);
							}
						}
					}

					index_out = index_out + 1;
				}

				index = index + 1;
			}
		}
	}

	println!("complete: {:?}", utxo_map);
}
