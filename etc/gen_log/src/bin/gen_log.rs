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

extern crate libc;
extern crate rand;
extern crate secp256k1;

use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value::Null;
use serde_json::{Error, Value};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::thread::JoinHandle;
use util::print_util::print;

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
	errfile: String,
	minheight: u32,
	maxheight: u32,
	#[structopt(short, long)]
	append: bool,
}

const MAX_THREAD_COUNT: usize = 16;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Cli::from_args();
	let rpcuser = args.rpcuser;
	let rpcpassword = args.rpcpassword;
	let rpcconnect = args.rpcconnect;
	let rpcport = args.rpcport;
	let outfile = args.outfile;
	let errfile = args.errfile;
	let min_height = args.minheight;
	let max_height = args.maxheight;
	let append = args.append;

	let network = Network::Bitcoin;

	let file;
	if !append {
		let _ = std::fs::remove_file(outfile.clone());
		file = OpenOptions::new().write(true).create(true).open(outfile)?;
	} else {
		file = OpenOptions::new().write(true).append(true).open(outfile)?;
	}

	let errfile = OpenOptions::new()
		.write(true)
		.create(true)
		.append(true)
		.open(errfile)?;

	for i in min_height..(max_height + 1) {
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
			let line = line.unwrap();
			print(format!("Processing block {}", i));
			let mut inner_cmd = Command::new("bitcoin-cli")
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

			let stdout = inner_cmd.stdout.as_mut().unwrap();
			let u: Result<BtcBlock, Error> = serde_json::from_reader(stdout);
			let u = u.unwrap();
			let arr = u.tx.unwrap();
			let mut index = 0;
			inner_cmd.wait()?;

			let mut handles: Vec<JoinHandle<_>> = Vec::new();
			let mut senders: Vec<Sender<String>> = Vec::new();
			let mut receivers: Vec<Receiver<String>> = Vec::new();
			for _ in 0..MAX_THREAD_COUNT {
				let (tx, rx): (Sender<String>, Receiver<String>) = channel();
				senders.push(tx);
				receivers.push(rx);
			}

			let mut counter = 0;
			loop {
				if arr[index] == Null {
					break;
				}

				let rpcuser = rpcuser.clone();
				let rpcpassword = rpcpassword.clone();
				let rpcconnect = rpcconnect.clone();
				let rpcport = rpcport.clone();
				let arr = arr.clone();
				let tx = &senders[counter];
				let tx = tx.clone();

				let next = thread::spawn(move || {
					let tx_id = &arr[index];
					let mut inner_inner_cmd = Command::new("bitcoin-cli")
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

					let stdout = inner_inner_cmd.stdout.as_mut().unwrap();
					let u: Result<BtcTransaction, Error> = serde_json::from_reader(stdout);
					let u = u.unwrap();
					let arr_in = u.vin.unwrap();
					let arr_out = u.vout.unwrap();

					let mut index_in = 0;
					let mut index_out = 0;
					inner_inner_cmd.wait().unwrap();

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
							tx.send(format!("rem {} {} {}\n", tx_id, index, i)).unwrap();
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
									for x in 0..1 {
										let address = address[x].as_str().unwrap().to_string();
										tx.send(format!(
											"add {} {} {} {} {}\n",
											address, tx_id, n, value, i,
										))
										.unwrap();
									}
								}
							} else {
								let asm = script_pub_key.get("asm");
								if asm.is_some() {
									let asm = asm.unwrap();
									let split = asm.as_str().unwrap().split(" ");
									let vec: Vec<&str> = split.collect();
									let hex = hex::decode(vec[0]);

									// TODO: Handle errors which means things like OP_DUP, etc
									if hex.is_ok() {
										let hex = hex.unwrap();
										let public_key = bitcoin::PublicKey::from_slice(&hex);
										if public_key.is_ok() {
											let public_key = public_key.unwrap();
											let address =
												Address::p2pkh(&public_key, network).to_string();
											tx.send(format!(
												"add {} {} {} {} {}\n",
												address, tx_id, n, value, i,
											))
											.unwrap();
										} else {
											tx.send(format!(
												"add {} {} {} {} {}\n",
												"none", tx_id, n, value, i,
											))
											.unwrap();
										}
									} else {
										// no address, send to 'none' for now.
										tx.send(format!(
											"add {} {} {} {} {}\n",
											"none", tx_id, n, value, i,
										))
										.unwrap();
									}

									//else {
									//	tx.send(format!(
									//		"ERROR: [block {}] hex decode failed: {}\n",
									//		i, asm
									//	))
									//	.unwrap();
									//}
								}
							}
						}

						index_out = index_out + 1;
					}
					tx.send("complete".to_string()).unwrap();
				});
				handles.push(next);

				if handles.len() >= MAX_THREAD_COUNT {
					clean_recv(&receivers, &file, &errfile, handles.len())?;
					for handle in handles {
						handle.join().expect("problem waiting to join");
					}
					handles = Vec::new();
					counter = 0;
				} else {
					counter = counter + 1;
				}

				index = index + 1;
			}

			clean_recv(&receivers, &file, &errfile, handles.len())?;
			for handle in handles {
				handle.join().expect("problem joining");
			}
		}

		cmd.wait()?;
	}

	Ok(())
}

fn clean_recv(
	recvs: &Vec<Receiver<String>>,
	file: &File,
	errfile: &File,
	len: usize,
) -> Result<(), Error> {
	let mut i = 0;
	let recvs = &*recvs;
	let mut file = &*file;
	let mut errfile = &*errfile;
	loop {
		if i == len {
			break;
		}

		let rx = &recvs[i];

		loop {
			let next = rx.recv().unwrap();
			if next == "complete" {
				break;
			} else if next.starts_with("ERROR: ") {
				write!(errfile, "{}", next).unwrap();
			} else {
				write!(file, "{}", next).unwrap();
			}
		}

		i = i + 1;
	}
	Ok(())
}
