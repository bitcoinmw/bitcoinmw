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

//! Server types
use crate::util::OnionV3AddressError;
use std::convert::From;
use std::sync::Arc;

use chrono::prelude::Utc;
use failure::{Context, Fail};
use rand::prelude::*;
use std::time::SystemTimeError;

use crate::core::global::{ChainTypes, DEFAULT_FUTURE_TIME_LIMIT};
pub use crate::core::{core, libtx, pow};
use crate::p2p;
use crate::pool;
use crate::pool::types::DandelionConfig;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// Tor Configuration Error
	#[fail(display = "Tor Config Error: {}", _0)]
	TorConfig(String),

	/// Configuration Error
	#[fail(display = "Configuration Error: {}", _0)]
	Configuration(String),

	/// Argument Error
	#[fail(display = "Argument Error: {}", _0)]
	ArgumentError(String),

	/// RecvError
	#[fail(display = "RecvError: {}", _0)]
	RecvError(String),

	/// Error origining for a Core Error
	#[fail(display = "Core Error: {}", _0)]
	Core(String),

	/// Wallet communication Error
	#[fail(display = "Wallet comm Error: {}", _0)]
	WalletComm(String),

	/// Chain Error
	#[fail(display = "Chain error: {}", _0)]
	Chain(String),

	/// Tor Process error
	#[fail(display = "Tor Process Error: {}", _0)]
	TorProcess(String),

	/// Onion V3 Address Error
	#[fail(display = "Onion V3 Address Error: {}", _0)]
	OnionV3Address(String),

	/// Error when formatting json
	#[fail(display = "IO error, {}", _0)]
	IO(String),

	/// Generating ED25519 Public Key
	#[fail(display = "Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Checking for onion address
	#[fail(display = "Address is not an Onion v3 Address: {}", _0)]
	NotOnion(String),

	/// Internal error
	#[fail(display = "Internal Error: {}", _0)]
	InternalError(String),

	/// API Error
	#[fail(display = "API Error: {}", _0)]
	API(String),

	/// P2P Error
	#[fail(display = "P2P Error: {}", _0)]
	P2P(String),

	/// Error originating from a Block error
	#[fail(display = "Block Error: {}", _0)]
	Block(String),

	/// KeyChain Error
	#[fail(display = "Keychain Error: {}", _0)]
	KeyChain(String),
}

/// Error definition
#[derive(Debug)]
pub struct Error {
	/// Inner Error
	pub inner: Context<ErrorKind>,
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<failure::Context<ErrorKind>> for Error {
	fn from(e: failure::Context<ErrorKind>) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(e.to_string())),
		}
	}
}

impl From<SystemTimeError> for Error {
	fn from(e: SystemTimeError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!(
				"SystemTimeError: {:?}",
				e
			))),
		}
	}
}

impl From<grin_core::address::Error> for Error {
	fn from(e: grin_core::address::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("{:?}", e))),
		}
	}
}

impl From<bmw_utxo::error::Error> for Error {
	fn from(e: bmw_utxo::error::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(format!("{:?}", e))),
		}
	}
}

impl From<std::sync::mpsc::RecvError> for Error {
	fn from(e: std::sync::mpsc::RecvError) -> Error {
		Error {
			inner: Context::new(ErrorKind::InternalError(e.to_string())),
		}
	}
}

impl From<OnionV3AddressError> for Error {
	fn from(error: OnionV3AddressError) -> Error {
		Error {
			inner: Context::new(ErrorKind::OnionV3Address(error.to_string())),
		}
	}
}

impl From<grin_keychain::Error> for Error {
	fn from(error: grin_keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::KeyChain(error.to_string())),
		}
	}
}

impl From<grin_p2p::Error> for Error {
	fn from(error: grin_p2p::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::P2P(format!("{:?}", error))),
		}
	}
}

impl From<grin_api::Error> for Error {
	fn from(error: grin_api::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::API(error.to_string())),
		}
	}
}

impl From<grin_chain::Error> for Error {
	fn from(error: grin_chain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Chain(error.to_string())),
		}
	}
}

impl From<grin_core::core::block::Error> for Error {
	fn from(error: grin_core::core::block::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Block(error.to_string())),
		}
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IO(error.to_string())),
		}
	}
}

/// Type of seeding the server will use to find other peers on the network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChainValidationMode {
	/// Run full chain validation after processing every block.
	EveryBlock,
	/// Do not automatically run chain validation during normal block
	/// processing.
	Disabled,
}

impl Default for ChainValidationMode {
	fn default() -> ChainValidationMode {
		ChainValidationMode::Disabled
	}
}

/// Full server configuration, aggregating configurations required for the
/// different components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
	/// Directory under which the rocksdb stores will be created
	pub db_root: String,

	/// Network address for the Rest API HTTP server.
	pub api_http_addr: String,

	/// Location of secret for basic auth on Rest API HTTP and V2 Owner API server.
	pub api_secret_path: Option<String>,

	/// Location of secret for basic auth on v2 Foreign API server.
	pub foreign_api_secret_path: Option<String>,

	/// TLS certificate file
	pub tls_certificate_file: Option<String>,
	/// TLS certificate private key file
	pub tls_certificate_key: Option<String>,

	/// Location of the bitcoin utxo binary
	pub binary_location: Option<String>,

	/// Setup the server for tests, testnet or mainnet
	#[serde(default)]
	pub chain_type: ChainTypes,

	/// Future Time Limit
	#[serde(default = "default_future_time_limit")]
	pub future_time_limit: u64,

	/// Automatically run full chain validation during normal block processing?
	#[serde(default)]
	pub chain_validation_mode: ChainValidationMode,

	/// Whether this node is a full archival node or a fast-sync, pruned node
	pub archive_mode: Option<bool>,

	/// Whether to skip the sync timeout on startup
	/// (To assist testing on solo chains)
	pub skip_sync_wait: Option<bool>,

	/// Whether to skip sync altogether (used in testing)
	pub skip_sync: Option<bool>,

	/// Whether to run the TUI
	/// if enabled, this will disable logging to stdout
	pub run_tui: Option<bool>,

	/// Whether to run the test miner (internal, cuckoo 16)
	pub run_test_miner: Option<bool>,

	/// Test miner wallet URL
	pub test_miner_wallet_url: Option<String>,

	/// Configuration for the peer-to-peer server
	pub p2p_config: p2p::P2PConfig,

	/// Transaction pool configuration
	#[serde(default)]
	pub pool_config: pool::PoolConfig,

	/// Dandelion configuration
	#[serde(default)]
	pub dandelion_config: pool::DandelionConfig,

	/// Configuration for the mining daemon
	#[serde(default)]
	pub stratum_mining_config: Option<StratumServerConfig>,

	/// Configuration for the webhooks that trigger on certain events
	#[serde(default)]
	pub webhook_config: WebHooksConfig,

	/// Bypass the checksum check for the utxo_data (must only be used for testing)
	pub bypass_checksum: Option<bool>,
}

fn default_future_time_limit() -> u64 {
	DEFAULT_FUTURE_TIME_LIMIT
}

impl Default for ServerConfig {
	fn default() -> ServerConfig {
		ServerConfig {
			db_root: "bmw_chain".to_string(),
			api_http_addr: "127.0.0.1:3413".to_string(),
			api_secret_path: Some(".api_secret".to_string()),
			foreign_api_secret_path: Some(".foreign_api_secret".to_string()),
			tls_certificate_file: None,
			tls_certificate_key: None,
			p2p_config: p2p::P2PConfig::default(),
			dandelion_config: pool::DandelionConfig::default(),
			stratum_mining_config: Some(StratumServerConfig::default()),
			chain_type: ChainTypes::default(),
			future_time_limit: default_future_time_limit(),
			archive_mode: Some(false),
			chain_validation_mode: ChainValidationMode::default(),
			pool_config: pool::PoolConfig::default(),
			skip_sync_wait: Some(false),
			skip_sync: Some(false),
			run_tui: Some(true),
			run_test_miner: Some(false),
			test_miner_wallet_url: None,
			webhook_config: WebHooksConfig::default(),
			binary_location: None,
			bypass_checksum: None,
		}
	}
}

/// Stratum (Mining server) configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StratumServerConfig {
	/// Run a stratum mining server (the only way to communicate to mine this
	/// node via grin-miner
	pub enable_stratum_server: Option<bool>,

	/// If enabled, the address and port to listen on
	pub stratum_server_addr: Option<String>,

	/// How long to wait before stopping the miner, recollecting transactions
	/// and starting again
	pub attempt_time_per_block: u32,

	/// Minimum difficulty for worker shares
	pub minimum_share_difficulty: u64,

	/// Base address to the HTTP wallet receiver
	pub recipient_address: String,

	/// Attributes the reward to a random private key instead of contacting the
	/// wallet receiver. Mostly used for tests.
	pub burn_reward: bool,
}

impl Default for StratumServerConfig {
	fn default() -> StratumServerConfig {
		StratumServerConfig {
			recipient_address: "replace".to_string(),
			burn_reward: false,
			attempt_time_per_block: 15,
			minimum_share_difficulty: 1,
			enable_stratum_server: Some(false),
			stratum_server_addr: Some("127.0.0.1:3416".to_string()),
		}
	}
}

/// Web hooks configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebHooksConfig {
	/// url to POST transaction data when a new transaction arrives from a peer
	pub tx_received_url: Option<String>,
	/// url to POST header data when a new header arrives from a peer
	pub header_received_url: Option<String>,
	/// url to POST block data when a new block arrives from a peer
	pub block_received_url: Option<String>,
	/// url to POST block data when a new block is accepted by our node (might be a reorg or a fork)
	pub block_accepted_url: Option<String>,
	/// number of worker threads in the tokio runtime
	#[serde(default = "default_nthreads")]
	pub nthreads: u16,
	/// timeout in seconds for the http request
	#[serde(default = "default_timeout")]
	pub timeout: u16,
}

fn default_timeout() -> u16 {
	10
}

fn default_nthreads() -> u16 {
	4
}

impl Default for WebHooksConfig {
	fn default() -> WebHooksConfig {
		WebHooksConfig {
			tx_received_url: None,
			header_received_url: None,
			block_received_url: None,
			block_accepted_url: None,
			nthreads: default_nthreads(),
			timeout: default_timeout(),
		}
	}
}

/// A node is either "stem" of "fluff" for the duration of a single epoch.
/// A node also maintains an outbound relay peer for the epoch.
#[derive(Debug)]
pub struct DandelionEpoch {
	config: DandelionConfig,
	// When did this epoch start?
	start_time: Option<i64>,
	// Are we in "stem" mode or "fluff" mode for this epoch?
	is_stem: bool,
	// Our current Dandelion relay peer (effective for this epoch).
	relay_peer: Option<Arc<p2p::Peer>>,
}

impl DandelionEpoch {
	/// Create a new Dandelion epoch, defaulting to "stem" and no outbound relay peer.
	pub fn new(config: DandelionConfig) -> DandelionEpoch {
		DandelionEpoch {
			config,
			start_time: None,
			is_stem: true,
			relay_peer: None,
		}
	}

	/// Is the current Dandelion epoch expired?
	/// It is expired if start_time is older than the configured epoch_secs.
	pub fn is_expired(&self) -> bool {
		match self.start_time {
			None => true,
			Some(start_time) => {
				let epoch_secs = self.config.epoch_secs;
				Utc::now().timestamp().saturating_sub(start_time) > epoch_secs as i64
			}
		}
	}

	/// Transition to next Dandelion epoch.
	/// Select stem/fluff based on configured stem_probability.
	/// Choose a new outbound stem relay peer.
	pub fn next_epoch(&mut self, peers: &Arc<p2p::Peers>) {
		self.start_time = Some(Utc::now().timestamp());
		self.relay_peer = peers.iter().outbound().connected().choose_random();

		// If stem_probability == 90 then we stem 90% of the time.
		let stem_probability = self.config.stem_probability;
		let mut rng = rand::thread_rng();
		self.is_stem = rng.gen_range(0, 100) < stem_probability;

		let addr = self.relay_peer.clone().map(|p| p.info.addr.clone());
		info!(
			"DandelionEpoch: next_epoch: is_stem: {} ({}%), relay: {:?}",
			self.is_stem, stem_probability, addr
		);
	}

	/// Are we stemming (or fluffing) transactions in this epoch?
	pub fn is_stem(&self) -> bool {
		self.is_stem
	}

	/// Always stem our (pushed via api) txs regardless of stem/fluff epoch?
	pub fn always_stem_our_txs(&self) -> bool {
		self.config.always_stem_our_txs
	}

	/// What is our current relay peer?
	/// If it is not connected then choose a new one.
	pub fn relay_peer(&mut self, peers: &Arc<p2p::Peers>) -> Option<Arc<p2p::Peer>> {
		let mut update_relay = false;
		if let Some(peer) = &self.relay_peer {
			if !peer.is_connected() {
				info!(
					"DandelionEpoch: relay_peer: {:?} not connected, choosing a new one.",
					peer.info.addr
				);
				update_relay = true;
			}
		} else {
			update_relay = true;
		}

		if update_relay {
			self.relay_peer = peers.iter().outbound().connected().choose_random();
			info!(
				"DandelionEpoch: relay_peer: new peer chosen: {:?}",
				self.relay_peer.clone().map(|p| p.info.addr.clone())
			);
		}

		self.relay_peer.clone()
	}
}
