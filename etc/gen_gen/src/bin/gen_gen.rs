// Copyright 2020 The Grin Developers
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

//! Main for building the genesis generation utility.

use crate::core::global;
use grin_core::ser::ProtocolVersion;
use std::sync::Arc;
use std::{fs, path};

use chrono::prelude::Utc;
use chrono::Duration;
use curl;
use serde_json;

use cuckoo_miner as cuckoo;
use grin_chain as chain;
use grin_core as core;
use grin_miner_plugin as plugin;
use grin_util::{self as util, ToHex};

use grin_core::core::hash::Hashed;
use grin_core::core::verifier_cache::LruVerifierCache;
use grin_keychain::BlindingFactor;

static BCHAIN_INFO_URL: &str = "https://blockchain.info/latestblock";
static BCYPHER_URL: &str = "https://api.blockcypher.com/v1/btc/main";
static BCHAIR_URL: &str = "https://api.blockchair.com/bitcoin/blocks?limit=2";

static GENESIS_RS_PATH: &str = "../../core/src/genesis.rs";
static PLUGIN_PATH: &str =
	"../../../grin-miner/target/release/plugins/cuckarood_cpu_compat_29.cuckooplugin";

fn main() {
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	if !path::Path::new(GENESIS_RS_PATH).exists() {
		panic!(
			"File {} not found, make sure you're running this from the gen_gen directory",
			GENESIS_RS_PATH
		);
	}
	if !path::Path::new(PLUGIN_PATH).exists() {
		panic!(
			"File {} not found, make sure you're running this from the gen_gen directory",
			PLUGIN_PATH
		);
	}

	// get the latest bitcoin hash
	let h1 = get_bchain_head();
	let h2 = get_bcypher_head();
	let h3 = get_bchair_head();

	if h1 != h2 || h1 != h3 {
		panic!(
			"Bitcoin chain head is inconsistent, please retry ({}, {}, {}).",
			h1, h2, h3
		);
	}

	println!("Using bitcoin block hash {}", h1);

	// build the basic parts of the genesis block header
	let mut gen = core::genesis::genesis_main();

	gen = gen.without_reward();

	{
		// setup a tmp chain to set block header roots
		core::global::set_local_chain_type(core::global::ChainTypes::UserTesting);
		let tmp_chain = setup_chain(".bmw.tmp", core::pow::mine_genesis_block().unwrap());
		tmp_chain.set_txhashset_roots(&mut gen).unwrap();
	}

	// sets the timestamp and prev_root from the bitcoin block (needs to be
	// after set_txhashset roots to not get overwritten)
	gen.header.timestamp = Utc::now() + Duration::minutes(45);
	gen.header.prev_root = core::core::hash::Hash::from_hex(&h1).unwrap();

	// mine a Cuckaroo29 block
	core::global::set_local_chain_type(core::global::ChainTypes::Mainnet);
	let plugin_lib = cuckoo::PluginLibrary::new(PLUGIN_PATH).unwrap();
	let mut params = plugin_lib.get_default_params();
	params.mutate_nonce = false;
	let solver_ctx = plugin_lib.create_solver_ctx(&mut params);

	let mut solver_sols = plugin::SolverSolutions::default();
	let mut solver_stats = plugin::SolverStats::default();
	let mut nonce = 0;
	while solver_sols.num_sols == 0 {
		println!("Attempts = {}", nonce);
		solver_sols = plugin::SolverSolutions::default();
		gen.header.pow.nonce = nonce;
		let _ = plugin_lib.run_solver(
			solver_ctx,
			gen.header.pre_pow(),
			nonce,
			1,
			&mut solver_sols,
			&mut solver_stats,
		);
		if solver_stats.has_errored {
			println!(
				"Plugin {} has errored, device: {}. Reason: {}",
				solver_stats.get_plugin_name(),
				solver_stats.get_device_name(),
				solver_stats.get_error_reason(),
			);
			return;
		}

		nonce += 1;
	}

	// Set the PoW solution and make sure the block is mostly valid
	gen.header.pow.proof.nonces = solver_sols.sols[0].to_u64s();
	assert!(gen.header.pow.is_secondary(), "Not a secondary header");
	println!("Built genesis:\n{:?}", gen);
	core::pow::verify_size(&gen.header).unwrap();
	gen.validate(
		&BlindingFactor::zero(),
		Arc::new(util::RwLock::new(LruVerifierCache::new())),
		None,
	)
	.unwrap();

	println!("\nFinal genesis cyclehash: {}", gen.hash().to_hex());
	let gen_bin = core::ser::ser_vec(&gen, ProtocolVersion(1)).unwrap();
	println!("Final genesis full hash: {}\n", gen_bin.hash().to_hex());

	update_genesis_rs(&gen);
	println!("genesis.rs has been updated, check it and run mainnet_genesis_hash test");
	println!("also check bitcoin block {} hasn't been orphaned.", h1);
	println!("All done!");
}

fn update_genesis_rs(gen: &core::core::Block) {
	println!(
		"{}, {}",
		"prev_root".to_string(),
		format!(
			"Hash::from_hex(\"{}\").unwrap()",
			gen.header.prev_root.to_hex()
		),
	);
	println!(
		"{}, {}",
		"output_root".to_string(),
		format!(
			"Hash::from_hex(\"{}\").unwrap()",
			gen.header.output_root.to_hex()
		),
	);
	println!(
		"{}, {}",
		"range_proof_root".to_string(),
		format!(
			"Hash::from_hex(\"{}\").unwrap()",
			gen.header.range_proof_root.to_hex()
		),
	);
	println!(
		"{}, {}",
		"kernel_root".to_string(),
		format!(
			"Hash::from_hex(\"{}\").unwrap()",
			gen.header.kernel_root.to_hex()
		),
	);
	println!(
		"{}, {}",
		"total_kernel_offset".to_string(),
		format!(
			"BlindingFactor::from_hex(\"{}\").unwrap()",
			gen.header.total_kernel_offset.to_hex()
		),
	);
	println!(
		"{}, {}",
		"nonces".to_string(),
		format!("vec!{:?}", gen.header.pow.proof.nonces),
	);
}

fn setup_chain(dir_name: &str, genesis: core::core::Block) -> chain::Chain {
	util::init_test_logger();
	let _ = fs::remove_dir_all(dir_name);
	let verifier_cache = Arc::new(util::RwLock::new(
		core::core::verifier_cache::LruVerifierCache::new(),
	));
	chain::Chain::init(
		dir_name.to_string(),
		Arc::new(chain::types::NoopAdapter {}),
		genesis,
		core::pow::verify_size,
		verifier_cache,
		false,
		None,
	)
	.unwrap()
}

fn get_bchain_head() -> String {
	get_json(BCHAIN_INFO_URL)["hash"]
		.as_str()
		.unwrap()
		.to_string()
}

fn get_bcypher_head() -> String {
	get_json(BCYPHER_URL)["hash"].as_str().unwrap().to_string()
}

fn get_bchair_head() -> String {
	get_json(BCHAIR_URL)["data"][0]["hash"]
		.as_str()
		.unwrap()
		.to_string()
}

fn get_json(url: &str) -> serde_json::Value {
	let mut body = Vec::new();
	let mut easy = curl::easy::Easy::new();
	easy.url(url).unwrap();
	{
		let mut transfer = easy.transfer();
		transfer
			.write_function(|data| {
				body.extend_from_slice(data);
				Ok(data.len())
			})
			.unwrap();
		transfer.perform().unwrap();
	}
	serde_json::from_slice(&body).unwrap()
}
