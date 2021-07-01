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

//! Grin server implementation, glues the different parts of the system (mostly
//! the peer-to-peer server, the blockchain and the transaction pool) and acts
//! as a facade.

use crate::common::stats::UtxoStats;
use crate::tor::config as tor_config;
use crate::tor::process as tor_process;
use crate::util::secp;
use bmw_utxo::utxo_data::UtxoData;
use grin_core::address::Address;
use grin_util::OnionV3Address;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::{convert::TryInto, fs};
use std::{
	thread::{self, JoinHandle},
	time::{self, Duration},
};

use crate::api;
use crate::api::TLSConfig;
use crate::chain::{self, SyncState, SyncStatus};
use crate::common::adapters::{
	ChainToPoolAndNetAdapter, NetToChainAdapter, PoolToChainAdapter, PoolToNetAdapter,
};
use crate::common::hooks::{init_chain_hooks, init_net_hooks};
use crate::common::stats::{
	ChainStats, DiffBlock, DiffStats, PeerStats, ServerStateInfo, ServerStats, TxStats,
};
use crate::common::types::{Error, ErrorKind, ServerConfig, StratumServerConfig};
use crate::core::core::hash::Hashed;
use crate::core::core::verifier_cache::LruVerifierCache;
use crate::core::ser::ProtocolVersion;
use crate::core::{consensus, genesis, global, pow};
use crate::grin::{dandelion_monitor, seed, sync};
use crate::mining::stratumserver;
use crate::mining::test_miner::Miner;
use crate::p2p;
use crate::p2p::types::{Capabilities, PeerAddr};
use crate::pool;
use crate::tor::process::TorProcess;
use crate::util::file::get_first_line;
use crate::util::{RwLock, StopState};
use fs2::FileExt;
use grin_util::logger::LogEntry;
use grin_util::secp::Secp256k1;
use std::sync::mpsc::{Receiver, Sender};
use walkdir::WalkDir;

/// Arcified  thread-safe TransactionPool with type parameters used by server components
pub type ServerTxPool =
	Arc<RwLock<pool::TransactionPool<PoolToChainAdapter, PoolToNetAdapter, LruVerifierCache>>>;
/// Arcified thread-safe LruVerifierCache
pub type ServerVerifierCache = Arc<RwLock<LruVerifierCache>>;

/// Grin server holding internal structures.
pub struct Server {
	/// server config
	pub config: ServerConfig,
	/// handle to our network server
	pub p2p: Arc<p2p::Server>,
	/// data store access
	pub chain: Arc<chain::Chain>,
	/// in-memory transaction pool
	pub tx_pool: ServerTxPool,
	/// Shared cache for verification results when
	/// verifying rangeproof and kernel signatures.
	verifier_cache: ServerVerifierCache,
	/// Whether we're currently syncing
	pub sync_state: Arc<SyncState>,
	/// To be passed around to collect stats and info
	state_info: ServerStateInfo,
	/// Stop flag
	pub stop_state: Arc<StopState>,
	/// Maintain a lock_file so we do not run multiple Grin nodes from same dir.
	lock_file: Arc<File>,
	connect_thread: Option<JoinHandle<()>>,
	sync_thread: JoinHandle<()>,
	dandelion_thread: JoinHandle<()>,
	utxo_data: Arc<RwLock<UtxoData>>,
	/// Used to keep TorProcess in scope.
	_tor_process: Option<TorProcess>,
}

impl Server {
	/// Instantiates and starts a new server. Optionally takes a callback
	/// for the server to send an ARC copy of itself, to allow another process
	/// to poll info about the server status
	pub fn start<F>(
		config: ServerConfig,
		logs_rx: Option<mpsc::Receiver<LogEntry>>,
		mut info_callback: F,
	) -> Result<(), Error>
	where
		F: FnMut(Server, Option<mpsc::Receiver<LogEntry>>),
	{
		let mining_config = config.stratum_mining_config.clone();
		let enable_test_miner = config.run_test_miner;
		let test_miner_wallet_url = config.test_miner_wallet_url.clone();
		let serv = Server::new(config)?;

		if let Some(c) = mining_config {
			let enable_stratum_server = c.enable_stratum_server;
			if let Some(s) = enable_stratum_server {
				if s {
					{
						let mut stratum_stats = serv.state_info.stratum_stats.write();
						stratum_stats.is_enabled = true;
					}
					serv.start_stratum_server(c);
				}
			}
		}

		if let Some(s) = enable_test_miner {
			if s {
				serv.start_test_miner(test_miner_wallet_url, serv.stop_state.clone());
			}
		}

		info_callback(serv, logs_rx);
		Ok(())
	}

	// Exclusive (advisory) lock_file to ensure we do not run multiple
	// instance of grin server from the same dir.
	// This uses fs2 and should be safe cross-platform unless somebody abuses the file itself.
	fn one_grin_at_a_time(config: &ServerConfig) -> Result<Arc<File>, Error> {
		let path = Path::new(&config.db_root);
		fs::create_dir_all(&path)?;
		let path = path.join("bmw.lock");
		let lock_file = fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.open(&path)?;
		lock_file.try_lock_exclusive().map_err(|e| {
			let mut stderr = std::io::stderr();
			writeln!(
				&mut stderr,
				"Failed to lock {:?} (bmw server already running?)",
				path
			)
			.expect("Could not write to stderr");
			e
		})?;
		Ok(Arc::new(lock_file))
	}

	fn validate_config(config: ServerConfig) -> Result<(), Error> {
		if config.stratum_mining_config.is_some() {
			let stratum_config = config.stratum_mining_config.unwrap();
			if stratum_config.enable_stratum_server.is_some() {
				let enable_stratum_server = stratum_config.enable_stratum_server.unwrap();
				if enable_stratum_server {
					let address = Address::from_str(&stratum_config.recipient_address);
					if address.is_err() && !stratum_config.burn_reward {
						return Err(ErrorKind::Configuration(format!(
							"recipient_address [\"{}\"] is not valid",
							stratum_config.recipient_address
						))
						.into());
					} else if !address.is_err() {
						let address = address.unwrap();
						if address.network != config.chain_type {
							return Err(ErrorKind::Configuration(format!(
								"recipient_address [\"{}\"] is not valid. \
Wrong network! {:?} != {:?}",
								stratum_config.recipient_address,
								address.network,
								config.chain_type,
							))
							.into());
						}
					}
				}
			}
		}

		Ok(())
	}

	/// Instantiates a new server associated with the provided future reactor.
	pub fn new(config: ServerConfig) -> Result<Server, Error> {
		// Obtain our lock_file or fail immediately with an error.
		let lock_file = Server::one_grin_at_a_time(&config)?;

		Server::validate_config(config.clone())?;

		// Defaults to None (optional) in config file.
		// This translates to false here.
		let archive_mode = match config.archive_mode {
			None => false,
			Some(b) => b,
		};

		let stop_state = Arc::new(StopState::new());

		// Shared cache for verification results.
		// We cache rangeproof verification and kernel signature verification.
		let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

		let pool_adapter = Arc::new(PoolToChainAdapter::new());
		let pool_net_adapter = Arc::new(PoolToNetAdapter::new(config.dandelion_config.clone()));
		let tx_pool = Arc::new(RwLock::new(pool::TransactionPool::new(
			config.pool_config.clone(),
			pool_adapter.clone(),
			verifier_cache.clone(),
			pool_net_adapter.clone(),
		)));

		let sync_state = Arc::new(SyncState::new());

		let chain_adapter = Arc::new(ChainToPoolAndNetAdapter::new(
			tx_pool.clone(),
			init_chain_hooks(&config),
		));

		let genesis = match config.chain_type {
			global::ChainTypes::AutomatedTesting | global::ChainTypes::PerfTesting => {
				pow::mine_genesis_block().unwrap()
			}
			global::ChainTypes::UserTesting => pow::mine_genesis_block().unwrap(),
			global::ChainTypes::Testnet => genesis::genesis_test(),
			global::ChainTypes::Mainnet => genesis::genesis_main(),
		};

		info!("Starting server, genesis block: {}", genesis.hash());

		let chain_type = if config.bypass_checksum.unwrap_or(false) {
			bmw_utxo::utxo_data::ChainType::Bypass
		} else {
			match config.chain_type {
				global::ChainTypes::Mainnet => bmw_utxo::utxo_data::ChainType::Mainnet,
				global::ChainTypes::Testnet => bmw_utxo::utxo_data::ChainType::Testnet,
				_ => bmw_utxo::utxo_data::ChainType::Other,
			}
		};
		// load bitcoin utxo binary
		let binary_location = config
			.binary_location
			.clone()
			.unwrap_or(format!("{}/gen_bin.bin", config.db_root).to_string());
		info!("using binary_location={}", binary_location);
		let res: Result<UtxoData, Error> = if config.binary_location.is_none()
			&& !Path::new(&binary_location).exists()
		{
			warn!("UtxoData has not been synced yet");
			// we have not synced yet.
			Ok(UtxoData::new(chain_type)?)
		} else if config.bypass_checksum.unwrap_or(false) {
			let mut ret = UtxoData::new(chain_type)?;
			if ret.load_binary(&binary_location).is_err() {
				Err(ErrorKind::Configuration("Could not load the utxo binary".to_string()).into())
			} else {
				Ok(ret)
			}
		} else {
			match config.chain_type {
				global::ChainTypes::Mainnet => {
					let mut ret = UtxoData::new(chain_type)?;
					if ret.load_binary(&binary_location).is_err() {
						Err(
							ErrorKind::Configuration("Could not load the utxo binary".to_string())
								.into(),
						)
					} else {
						Ok(ret)
					}
				}
				global::ChainTypes::Testnet => {
					let mut ret = UtxoData::new(chain_type)?;
					if ret.load_binary(&binary_location).is_err() {
						Err(
							ErrorKind::Configuration("Could not load the utxo binary".to_string())
								.into(),
						)
					} else {
						Ok(ret)
					}
				}
				_ => {
					let mut ret = UtxoData::new(chain_type)?;
					if ret.load_binary(&binary_location).is_err() {
						Err(
							ErrorKind::Configuration("Could not load the utxo binary".to_string())
								.into(),
						)
					} else {
						Ok(ret)
					}
				}
			}
		};

		if res.is_err() {
			error!("Could not load binary: {:?}", res);
			println!("Could not load binary: {:?}", res);
			exit(0);
		}
		let utxo_data = res.unwrap();
		let utxo_data = Arc::new(RwLock::new(utxo_data));

		let shared_chain = Arc::new(chain::Chain::init(
			config.db_root.clone(),
			chain_adapter.clone(),
			genesis.clone(),
			pow::verify_size,
			verifier_cache.clone(),
			archive_mode,
			Some(Arc::downgrade(&utxo_data)),
		)?);

		pool_adapter.set_chain(shared_chain.clone());

		let net_adapter = Arc::new(NetToChainAdapter::new(
			sync_state.clone(),
			shared_chain.clone(),
			tx_pool.clone(),
			verifier_cache.clone(),
			config.clone(),
			init_net_hooks(&config),
		));

		// Use our default capabilities here.
		// We will advertize these to our peers during hand/shake.
		let capabilities = Capabilities::default();
		debug!("Capabilities: {:?}", capabilities);

		// setup tor connection here
		let (onion_address, socks_port, _tor_process) =
			Server::setup_tor(config.clone(), stop_state.clone())?;

		let p2p_server = Arc::new(p2p::Server::new(
			&config.db_root,
			capabilities,
			config.p2p_config.clone(),
			net_adapter.clone(),
			genesis.hash(),
			stop_state.clone(),
			socks_port,
			onion_address,
			Some(Arc::downgrade(&utxo_data)),
		)?);

		// Initialize various adapters with our dynamic set of connected peers.
		chain_adapter.init(p2p_server.peers.clone());
		pool_net_adapter.init(p2p_server.peers.clone());
		net_adapter.init(p2p_server.peers.clone());

		let mut connect_thread = None;

		if config.p2p_config.seeding_type != p2p::Seeding::Programmatic {
			let seeder = match config.p2p_config.seeding_type {
				p2p::Seeding::None => {
					warn!("No seed configured, will stay solo until connected to");
					seed::predefined_seeds(vec![])
				}
				p2p::Seeding::List => match &config.p2p_config.seeds {
					Some(seeds) => seed::predefined_seeds(seeds.peers.clone()),
					None => {
						return Err(ErrorKind::Configuration(
							"Seeds must be configured for seeding type List".to_string(),
						)
						.into());
					}
				},
				p2p::Seeding::DNSSeed => seed::default_dns_seeds(),
				_ => unreachable!(),
			};

			let preferred_peers = match &config.p2p_config.peers_preferred {
				Some(addrs) => addrs.peers.clone(),
				None => vec![],
			};

			connect_thread = Some(seed::connect_and_monitor(
				p2p_server.clone(),
				seeder,
				&preferred_peers,
				stop_state.clone(),
			)?);
		}

		// Defaults to None (optional) in config file.
		// This translates to false here so we do not skip by default.
		let skip_sync_wait = config.skip_sync_wait.unwrap_or(false);
		sync_state.update(SyncStatus::AwaitingPeers(!skip_sync_wait));

		let sync_thread = sync::run_sync(
			sync_state.clone(),
			p2p_server.peers.clone(),
			shared_chain.clone(),
			stop_state.clone(),
			utxo_data.clone(),
			binary_location,
		)?;

		let p2p_inner = p2p_server.clone();
		let _ = thread::Builder::new()
			.name("p2p-server".to_string())
			.spawn(move || {
				if let Err(e) = p2p_inner.listen() {
					error!("P2P server failed with erorr: {:?}", e);
				}
			})?;

		info!("Starting rest apis at: {}", &config.api_http_addr);
		let api_secret = get_first_line(config.api_secret_path.clone());
		let foreign_api_secret = get_first_line(config.foreign_api_secret_path.clone());
		let tls_conf = match config.tls_certificate_file.clone() {
			None => None,
			Some(file) => {
				let key = match config.tls_certificate_key.clone() {
					Some(k) => k,
					None => {
						let msg = "Private key for certificate is not set".to_string();
						return Err(ErrorKind::ArgumentError(msg).into());
					}
				};
				Some(TLSConfig::new(file, key))
			}
		};

		// TODO fix API shutdown and join this thread
		api::node_apis(
			&config.api_http_addr,
			shared_chain.clone(),
			tx_pool.clone(),
			p2p_server.peers.clone(),
			sync_state.clone(),
			api_secret,
			foreign_api_secret,
			tls_conf,
			utxo_data.clone(),
		)?;

		info!("Starting dandelion monitor: {}", &config.api_http_addr);
		let dandelion_thread = dandelion_monitor::monitor_transactions(
			config.dandelion_config.clone(),
			tx_pool.clone(),
			pool_net_adapter,
			verifier_cache.clone(),
			stop_state.clone(),
		)?;

		warn!("BMW server started.");
		Ok(Server {
			config,
			p2p: p2p_server,
			chain: shared_chain,
			tx_pool,
			verifier_cache,
			sync_state,
			state_info: ServerStateInfo {
				..Default::default()
			},
			stop_state,
			lock_file,
			connect_thread,
			sync_thread,
			dandelion_thread,
			utxo_data,
			_tor_process,
		})
	}

	/// Initialize the TOR listener for internal tor
	pub fn init_tor_listener(
		addr: &str,
		api_addr: &str,
		tor_base: Option<&str>,
		socks_port: u16,
	) -> Result<(String, TorProcess), Error> {
		let mut process = tor_process::TorProcess::new();
		let tor_dir = if tor_base.is_some() {
			format!("{}/tor/listener", tor_base.unwrap())
		} else {
			format!("{}/tor/listener", "~/.bmw/main")
		};

		let home_dir = dirs::home_dir()
			.map(|p| p.to_str().unwrap().to_string())
			.unwrap_or("~".to_string());
		let tor_dir = tor_dir.replace("~", &home_dir);

		// remove all other onion addresses that were previously used.

		let onion_service_dir = format!("{}/onion_service_addresses", tor_dir.clone());
		let mut onion_address = "".to_string();
		let mut found = false;
		if std::path::Path::new(&onion_service_dir).exists() {
			for entry in fs::read_dir(onion_service_dir)? {
				onion_address = entry.unwrap().file_name().into_string().unwrap();
				found = true;
			}
		}

		let mut sec_key_vec = None;
		let scoped_vec;
		let mut existing_onion = None;
		if !found {
			let sec_key = secp::key::SecretKey::new(&Secp256k1::new(), &mut rand::thread_rng());
			scoped_vec = vec![sec_key.clone()];
			sec_key_vec = Some((scoped_vec).as_slice());

			onion_address = OnionV3Address::from_private(&sec_key.0)
				.map_err(|e| {
					error!("unable to build onion address due to {:?}. Halting!", e);
					std::process::exit(-1);
				})
				.unwrap()
				.to_string();
		} else {
			existing_onion = Some(onion_address.clone());
		}
		tor_config::output_tor_listener_config(
			&tor_dir,
			addr,
			api_addr,
			sec_key_vec,
			existing_onion,
			socks_port,
		)
		.map_err(|e| {
			error!("failed to configure tor due to {:?}. Halting!", e);
			std::process::exit(-1);
		})
		.unwrap();

		info!(
			"Starting Tor inbound listener at address {}.onion, binding to {}",
			onion_address, addr
		);

		// Start Tor process
		let tor_path = PathBuf::from(format!("{}/torrc", tor_dir));
		let tor_path = fs::canonicalize(&tor_path)?;
		let tor_path = Server::adjust_canonicalization(tor_path);

		let res = process
			.torrc_path(&tor_path)
			.working_dir(&tor_dir)
			.timeout(200)
			.completion_percent(100)
			.launch();

		match res {
			Err(e) => Err(ErrorKind::Configuration(e.to_string()).into()),
			Ok(_) => Ok((onion_address.to_string(), process)),
		}
	}

	#[cfg(not(target_os = "windows"))]
	fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
		p.as_ref().display().to_string()
	}

	#[cfg(target_os = "windows")]
	fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
		const VERBATIM_PREFIX: &str = r#"\\?\"#;
		let p = p.as_ref().display().to_string();
		if p.starts_with(VERBATIM_PREFIX) {
			p[VERBATIM_PREFIX.len()..].to_string()
		} else {
			p
		}
	}

	fn setup_tor(
		config: ServerConfig,
		stop_state: Arc<StopState>,
	) -> Result<(String, u16, Option<TorProcess>), Error> {
		let o = config.p2p_config.onion_address.clone();

		if o.is_some() && !config.p2p_config.tor_external {
			return Err(ErrorKind::Configuration(
				"onion_address cannot be specified when tor_external is true".to_string(),
			)
			.into());
		} else if !o.is_some() && config.p2p_config.tor_external {
			return Err(ErrorKind::Configuration(
				"With external_tor = true, onion_address must be specified".to_string(),
			)
			.into());
		}

		if config.p2p_config.tor_external {
			let onion_address = o.unwrap();
			Ok((onion_address, config.p2p_config.tor_port, None))
		} else {
			// setup internal tor here
			let (input, output): (
				Sender<(Option<TorProcess>, Option<String>)>,
				Receiver<(Option<TorProcess>, Option<String>)>,
			) = mpsc::channel();

			let cloned_config = config.clone();
			thread::Builder::new()
				.name("tor_listener".to_string())
				.spawn(move || {
					let res = Server::init_tor_listener(
						&format!(
							"{}:{}",
							cloned_config.p2p_config.host, cloned_config.p2p_config.port
						),
						&cloned_config.api_http_addr,
						Some(&cloned_config.db_root),
						cloned_config.p2p_config.tor_port,
					);

					match res {
						Ok((onion_address, tp)) => {
							input
								.send((Some(tp), Some(format!("{}.onion", onion_address.clone()))))
								.unwrap();
							loop {
								std::thread::sleep(std::time::Duration::from_millis(10));
								if stop_state.is_stopped() {
									break;
								}
							}
						}
						Err(e) => {
							input.send((None, None)).unwrap();
							error!("failed to start Tor due to: {:?}", e);
						}
					};
				})?;

			let resp = output.recv()?;
			if resp.0.is_none() {
				error!("TOR did not start! Halting.");
				std::process::exit(-1);
			}
			let onion_address = resp.1.unwrap();
			Ok((onion_address, config.p2p_config.tor_port, resp.0))
		}
	}

	/// Asks the server to connect to a peer at the provided network address.
	pub fn connect_peer(&self, addr: PeerAddr) -> Result<(), Error> {
		self.p2p.connect(addr)?;
		Ok(())
	}

	/// Ping all peers, mostly useful for tests to have connected peers share
	/// their heights
	pub fn ping_peers(&self) -> Result<(), Error> {
		let head = self.chain.head()?;
		self.p2p.peers.check_all(head.total_difficulty, head.height);
		Ok(())
	}

	/// Number of peers
	pub fn peer_count(&self) -> u32 {
		self.p2p
			.peers
			.iter()
			.connected()
			.count()
			.try_into()
			.unwrap()
	}

	/// Start a minimal "stratum" mining service on a separate thread
	pub fn start_stratum_server(&self, config: StratumServerConfig) {
		let proof_size = global::proofsize();
		let sync_state = self.sync_state.clone();

		let mut stratum_server = stratumserver::StratumServer::new(
			config,
			self.chain.clone(),
			self.tx_pool.clone(),
			self.verifier_cache.clone(),
			self.state_info.stratum_stats.clone(),
		);
		let _ = thread::Builder::new()
			.name("stratum_server".to_string())
			.spawn(move || {
				stratum_server.run_loop(proof_size, sync_state);
			});
	}

	/// Start mining for blocks internally on a separate thread. Relies on
	/// internal miner, and should only be used for automated testing. Burns
	/// reward if recipient_address is 'None'
	pub fn start_test_miner(&self, recipient_address: Option<String>, stop_state: Arc<StopState>) {
		info!("start_test_miner - start",);
		let sync_state = self.sync_state.clone();
		let recipient_address = match recipient_address.clone() {
			Some(u) => u,
			None => String::from("replace"),
		};

		let config = StratumServerConfig {
			attempt_time_per_block: 60,
			burn_reward: false,
			enable_stratum_server: None,
			stratum_server_addr: None,
			recipient_address: recipient_address.clone(),
			minimum_share_difficulty: 1,
		};

		let mut miner = Miner::new(
			config,
			self.chain.clone(),
			self.tx_pool.clone(),
			self.verifier_cache.clone(),
			stop_state,
			sync_state,
		);
		miner.set_debug_output_id(format!("Port {}", self.config.p2p_config.port));
		let _ = thread::Builder::new()
			.name("test_miner".to_string())
			.spawn(move || miner.run_loop(Some(recipient_address)));
	}

	/// The chain head
	pub fn head(&self) -> Result<chain::Tip, Error> {
		self.chain.head().map_err(|e| e.into())
	}

	/// The head of the block header chain
	pub fn header_head(&self) -> Result<chain::Tip, Error> {
		self.chain.header_head().map_err(|e| e.into())
	}

	/// The p2p layer protocol version for this node.
	pub fn protocol_version() -> ProtocolVersion {
		ProtocolVersion::local()
	}

	/// Returns a set of stats about this server. This and the ServerStats
	/// structure
	/// can be updated over time to include any information needed by tests or
	/// other consumers
	pub fn get_server_stats(&self) -> Result<ServerStats, Error> {
		let stratum_stats = self.state_info.stratum_stats.read().clone();

		// Fill out stats on our current difficulty calculation
		// TODO: check the overhead of calculating this again isn't too much
		// could return it from next_difficulty, but would rather keep consensus
		// code clean. This may be handy for testing but not really needed
		// for release
		let diff_stats = {
			let last_blocks: Vec<consensus::HeaderInfo> =
				global::difficulty_data_to_vector(self.chain.difficulty_iter()?)
					.into_iter()
					.collect();

			let tip_height = self.head()?.height as i64;
			let mut height = tip_height as i64 - last_blocks.len() as i64 + 1;

			let diff_entries: Vec<DiffBlock> = last_blocks
				.windows(2)
				.map(|pair| {
					let prev = &pair[0];
					let next = &pair[1];

					height += 1;

					DiffBlock {
						block_height: height,
						block_hash: next.block_hash,
						difficulty: next.difficulty.to_num(),
						time: next.timestamp,
						duration: next.timestamp - prev.timestamp,
						secondary_scaling: next.secondary_scaling,
						is_secondary: next.is_secondary,
					}
				})
				.collect();

			let block_time_sum = diff_entries.iter().fold(0, |sum, t| sum + t.duration);
			let block_diff_sum = diff_entries.iter().fold(0, |sum, d| sum + d.difficulty);
			DiffStats {
				height: height as u64,
				last_blocks: diff_entries,
				average_block_time: block_time_sum / (consensus::DMA_WINDOW - 1),
				average_difficulty: block_diff_sum / (consensus::DMA_WINDOW - 1),
				window_size: consensus::DMA_WINDOW,
			}
		};

		let peer_stats = self
			.p2p
			.peers
			.iter()
			.connected()
			.into_iter()
			.map(|p| PeerStats::from_peer(&p))
			.collect();

		// Updating TUI stats should not block any other processing so only attempt to
		// acquire various read locks with a timeout.
		let read_timeout = Duration::from_millis(500);

		let tx_stats = self.tx_pool.try_read_for(read_timeout).map(|pool| TxStats {
			tx_pool_size: pool.txpool.size(),
			tx_pool_kernels: pool.txpool.kernel_count(),
			stem_pool_size: pool.stempool.size(),
			stem_pool_kernels: pool.stempool.kernel_count(),
		});

		let head = self.chain.head_header()?;
		let head_stats = ChainStats {
			latest_timestamp: head.timestamp,
			height: head.height,
			last_block_h: head.hash(),
			total_difficulty: head.total_difficulty(),
		};

		let header_head = self.chain.header_head()?;
		let header = self.chain.get_block_header(&header_head.hash())?;
		let header_stats = ChainStats {
			latest_timestamp: header.timestamp,
			height: header.height,
			last_block_h: header.hash(),
			total_difficulty: header.total_difficulty(),
		};

		let disk_usage_bytes = WalkDir::new(&self.config.db_root)
			.min_depth(1)
			.max_depth(3)
			.into_iter()
			.filter_map(|entry| entry.ok())
			.filter_map(|entry| entry.metadata().ok())
			.filter(|metadata| metadata.is_file())
			.fold(0, |acc, m| acc + m.len());

		let disk_usage_gb = format!("{:.*}", 3, (disk_usage_bytes as f64 / 1_000_000_000_f64));
		let utxo_percent = {
			let utxo_data = self.utxo_data.read();
			utxo_data.load_percentage()
		};

		Ok(ServerStats {
			peer_count: self.peer_count(),
			chain_stats: head_stats,
			header_stats: header_stats,
			sync_status: self.sync_state.status(),
			disk_usage_gb: disk_usage_gb,
			stratum_stats: stratum_stats,
			peer_stats: peer_stats,
			diff_stats: diff_stats,
			tx_stats: tx_stats,
			utxo_stats: UtxoStats {
				percentage: utxo_percent,
			},
		})
	}

	/// Stop the server.
	pub fn stop(self) {
		{
			self.sync_state.update(SyncStatus::Shutdown);
			self.stop_state.stop();

			if let Some(connect_thread) = self.connect_thread {
				match connect_thread.join() {
					Err(e) => error!("failed to join to connect_and_monitor thread: {:?}", e),
					Ok(_) => info!("connect_and_monitor thread stopped"),
				}
			} else {
				info!("No active connect_and_monitor thread")
			}

			match self.sync_thread.join() {
				Err(e) => error!("failed to join to sync thread: {:?}", e),
				Ok(_) => info!("sync thread stopped"),
			}

			match self.dandelion_thread.join() {
				Err(e) => error!("failed to join to dandelion_monitor thread: {:?}", e),
				Ok(_) => info!("dandelion_monitor thread stopped"),
			}
		}
		// this call is blocking and makes sure all peers stop, however
		// we can't be sure that we stopped a listener blocked on accept, so we don't join the p2p thread
		self.p2p.stop();
		let _ = self.lock_file.unlock();
		warn!("Shutdown complete");
	}

	/// Pause the p2p server.
	pub fn pause(&self) {
		self.stop_state.pause();
		thread::sleep(time::Duration::from_secs(1));
		self.p2p.pause();
	}

	/// Resume p2p server.
	/// TODO - We appear not to resume the p2p server (peer connections) here?
	pub fn resume(&self) {
		self.stop_state.resume();
	}

	/// Stops the test miner without stopping the p2p layer
	pub fn stop_test_miner(&self, stop: Arc<StopState>) {
		stop.stop();
		info!("stop_test_miner - stop",);
	}
}
