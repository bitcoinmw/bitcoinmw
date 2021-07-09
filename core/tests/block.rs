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

mod common;
use crate::common::{new_block, tx1i2o, tx2i1o, txspend1i1o};
use crate::core::consensus::{self, OUTPUT_WEIGHT, TESTING_HARD_FORK_INTERVAL};
use crate::core::core::block::{Block, BlockHeader, Error, HeaderVersion, UntrustedBlockHeader};
use crate::core::core::hash::Hashed;
use crate::core::core::id::ShortIdentifiable;
use crate::core::core::transaction::{
	self, FeeFields, KernelFeatures, NRDRelativeHeight, Output, OutputFeatures, OutputIdentifier,
	Transaction,
};
use crate::core::core::verifier_cache::{LruVerifierCache, VerifierCache};
use crate::core::core::{Committed, CompactBlock};
use crate::core::libtx::build;
use crate::core::libtx::ProofBuilder;
use crate::core::{global, pow, ser};
use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use bmw_utxo::utxo_data::ChainType;
use bmw_utxo::utxo_data::UtxoData;
use chrono::Duration;
use grin_core as core;
use grin_core::address::Address;
use grin_core::core::Inputs;
use grin_core::core::RedeemScript;
use grin_core::core::TransactionBody;
use grin_core::core::TxKernel;
use grin_core::libtx::build::gen_address;
use grin_core::libtx::build::input_rand;
use grin_core::libtx::build::output;
use grin_core::libtx::build::output_rand;
use grin_core::libtx::proof::PaymentId;
use grin_core::libtx::reward;
use keychain::{BlindingFactor, ExtKeychain, Keychain};
use std::collections::HashMap;
use std::sync::Arc;
use util::secp::key::PublicKey;
use util::secp::key::SecretKey;
use util::secp::Signature;
use util::{secp, RwLock, ToHex};

// Setup test with AutomatedTesting chain_type;
fn test_setup() {
	util::init_test_logger();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
}

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

#[test]
fn too_large_block() {
	test_setup();

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let max_out = global::max_block_weight() / OUTPUT_WEIGHT;

	let mut pks = vec![];
	for n in 0..(max_out + 1) {
		pks.push(ExtKeychain::derive_key_id(1, n as u32, 0, 0, 0));
	}

	let mut parts = vec![];
	for _ in 0..max_out {
		parts.push(output_rand(5));
	}
	parts.append(&mut vec![input_rand(500000)]);

	let tx = build::transaction(
		KernelFeatures::Plain { fee: 2.into() },
		&parts,
		&keychain,
		&builder,
	);
	println!("tx={:?}", tx);
	let tx = tx.unwrap();

	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx], &keychain, &builder, &prev, &key_id);
	assert!(b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_err());
}

#[test]
// block with no inputs/outputs/kernels
// no fees, no reward, no coinbase
fn very_empty_block() {
	test_setup();
	let b = Block::with_header(BlockHeader::default());

	assert_eq!(
		b.verify_coinbase(),
		Err(Error::Secp(secp::Error::IncorrectCommitSum))
	);
}

#[test]
fn block_with_nrd_kernel_pre_post_hf3() {
	// we update this function to use HeaderVersion always == 1.
	// We leave original comments for context.

	// automated testing - HF{1|2|3} at block heights {3, 6, 9}
	// Enable the global NRD feature flag. NRD kernels valid at HF3 at height 9.
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let tx = build::transaction(
		KernelFeatures::NoRecentDuplicate {
			fee: 2.into(),
			relative_height: NRDRelativeHeight::new(1440).unwrap(),
		},
		&[input_rand(7), output_rand(5)],
		&keychain,
		&builder,
	)
	.unwrap();
	let txs = &[tx];

	let prev_height = 3 * TESTING_HARD_FORK_INTERVAL - 2;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(prev_height),
		..BlockHeader::default()
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0),
	);

	// Block is invalid at header version 3 if it contains an NRD kernel.
	assert_eq!(b.header.version, HeaderVersion(1));
	assert!(b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_ok());

	let prev_height = 3 * TESTING_HARD_FORK_INTERVAL - 1;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(prev_height),
		..BlockHeader::default()
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0),
	);

	// Block is valid at header version 4 (at HF height) if it contains an NRD kernel.
	assert_eq!(b.header.height, 3 * TESTING_HARD_FORK_INTERVAL);
	assert_eq!(b.header.version, HeaderVersion(1));
	assert!(b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_ok());

	let prev_height = 3 * TESTING_HARD_FORK_INTERVAL;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(prev_height),
		..BlockHeader::default()
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0),
	);

	// Block is valid at header version 4 if it contains an NRD kernel.
	// updated to v1
	assert_eq!(b.header.version, HeaderVersion(1));
	assert!(b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_ok());
}

#[test]
// builds a block with a tx spending another and check that cut_through occurred
fn block_with_cut_through() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let btx1 = tx2i1o();

	let (recipient_address1, pri_view1) = gen_address();
	let btx2 = build::transaction(
		KernelFeatures::Plain { fee: 2.into() },
		&[input_rand(7), output(5, recipient_address1)],
		&keychain,
		&builder,
	)
	.unwrap();

	// spending tx2 - reuse key_id2
	let spending_output = btx2.outputs()[0];
	let btx3 = txspend1i1o(5, &keychain, &builder, spending_output, pri_view1);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[btx1, btx2, btx3], &keychain, &builder, &prev, &key_id);

	// block should have been automatically compacted (including reward
	// output) and should still be valid
	b.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.unwrap();
	assert_eq!(b.inputs().len(), 3);
	assert_eq!(b.outputs().len(), 3);
}

#[test]
fn empty_block_with_coinbase_is_valid() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);

	assert_eq!(b.inputs().len(), 0);
	assert_eq!(b.outputs().len(), 1);
	assert_eq!(b.kernels().len(), 1);

	let coinbase_outputs = b
		.outputs()
		.iter()
		.filter(|out| out.is_coinbase())
		.cloned()
		.collect::<Vec<_>>();
	assert_eq!(coinbase_outputs.len(), 1);

	let coinbase_kernels = b
		.kernels()
		.iter()
		.filter(|out| out.is_coinbase())
		.cloned()
		.collect::<Vec<_>>();
	assert_eq!(coinbase_kernels.len(), 1);

	// the block should be valid here (single coinbase output with corresponding
	// txn kernel)
	assert!(b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_ok());
}

#[test]
// test that flipping the COINBASE flag on the output features
// invalidates the block and specifically it causes verify_coinbase to fail
// additionally verifying the merkle_inputs_outputs also fails
fn remove_coinbase_output_flag() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let output = b.outputs()[0];

	let output = Output::new(
		OutputFeatures::Plain,
		output.commitment(),
		output.proof(),
		output.identifier.r_sig,
		output.identifier.view_tag,
		output.identifier.nonce,
		output.identifier.onetime_pubkey,
	);

	let b = Block {
		body: b.body.replace_outputs(&[output]),
		..b
	};

	assert_eq!(b.verify_coinbase(), Err(Error::CoinbaseSumMismatch));
	assert!(b
		.verify_kernel_sums(b.overage(None), b.header.total_kernel_offset())
		.is_ok());

	// note that since the OutputFeatures is part of the r_sig message
	// the error is now an IncorrectSignature error instead of the previous
	// TODO: test should be updated to manually generate the r_sig such that
	// the CoinbaseSumMismatch error occurs.
	assert_eq!(
		format!(
			"{:?}",
			b.validate(&BlindingFactor::zero(), verifier_cache(), None)
		)
		.contains("IncorrectSignature"),
		true,
	);
}

#[test]
// test that flipping the COINBASE flag on the kernel features
// invalidates the block and specifically it causes verify_coinbase to fail
fn remove_coinbase_kernel_flag() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);

	let mut kernel = b.kernels()[0].clone();
	kernel.features = KernelFeatures::Plain {
		fee: FeeFields::zero(),
	};
	b.body = b.body.replace_kernel(kernel);

	// Flipping the coinbase flag results in kernels not summing correctly.
	assert_eq!(
		b.verify_coinbase(),
		Err(Error::Secp(secp::Error::IncorrectCommitSum))
	);

	// Also results in the block no longer validating correctly
	// because the message being signed on each tx kernel includes the kernel features.
	assert_eq!(
		b.validate(&BlindingFactor::zero(), verifier_cache(), None)
			.is_err(),
		true,
	);
}

#[test]
fn serialize_deserialize_header_version() {
	let mut vec1 = Vec::new();
	ser::serialize_default(&mut vec1, &1_u16).expect("serialization failed");

	let mut vec2 = Vec::new();
	ser::serialize_default(&mut vec2, &HeaderVersion(1)).expect("serialization failed");

	// Check that a header_version serializes to a
	// single u16 value with no extraneous bytes wrapping it.
	assert_eq!(vec1, vec2);

	// Check we can successfully deserialize a header_version.
	let version: HeaderVersion = ser::deserialize_default(&mut &vec2[..]).unwrap();
	assert_eq!(version.0, 1)
}

#[test]
fn serialize_deserialize_block_header() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let header1 = b.header;

	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &header1).expect("serialization failed");
	let header2: BlockHeader = ser::deserialize_default(&mut &vec[..]).unwrap();

	assert_eq!(header1.hash(), header2.hash());
	assert_eq!(header1, header2);
}

fn set_pow(header: &mut BlockHeader) {
	// Set valid pow on the block as we will test deserialization of this "untrusted" from the network.
	let edge_bits = global::min_edge_bits();
	header.pow.proof.edge_bits = edge_bits;
	pow::pow_size(
		header,
		pow::Difficulty::min_dma(),
		global::proofsize(),
		edge_bits,
	)
	.unwrap();
}

#[test]
fn deserialize_untrusted_header_weight() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);

	// Set excessively large output mmr size on the header.
	b.header.output_mmr_size = 10_000;
	b.header.kernel_mmr_size = 0;
	set_pow(&mut b.header);

	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b.header).expect("serialization failed");
	let res: Result<UntrustedBlockHeader, _> = ser::deserialize_default(&mut &vec[..]);
	assert_eq!(res.err(), Some(ser::Error::CorruptedData));

	// Set excessively large kernel mmr size on the header.
	b.header.output_mmr_size = 0;
	b.header.kernel_mmr_size = 10_000;
	set_pow(&mut b.header);

	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b.header).expect("serialization failed");
	let res: Result<UntrustedBlockHeader, _> = ser::deserialize_default(&mut &vec[..]);
	assert_eq!(res.err(), Some(ser::Error::CorruptedData));

	// Set reasonable mmr sizes on the header to confirm the header can now be read "untrusted".
	b.header.output_mmr_size = 1;
	b.header.kernel_mmr_size = 1;
	set_pow(&mut b.header);

	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b.header).expect("serialization failed");
	let res: Result<UntrustedBlockHeader, _> = ser::deserialize_default(&mut &vec[..]);
	assert!(res.is_ok());
}

#[test]
fn serialize_deserialize_block() {
	test_setup();
	let tx1 = tx1i2o();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);

	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b).expect("serialization failed");
	let b2: Block = ser::deserialize_default(&mut &vec[..]).unwrap();

	assert_eq!(b.hash(), b2.hash());
	assert_eq!(b.header, b2.header);
	assert_eq!(b.inputs(), b2.inputs());
	assert_eq!(b.outputs(), b2.outputs());
	assert_eq!(b.kernels(), b2.kernels());
}

#[test]
fn empty_block_serialized_size() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b).expect("serialization failed");
	assert_eq!(vec.len(), 1_227 + 8 + 8 + 40);
}

#[test]
fn block_single_tx_serialized_size() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let tx1 = tx1i2o();
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);

	// Default protocol version (3)
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b).expect("serialization failed");
	assert_eq!(vec.len(), 3_062 + 8 + 8 + 40 + 64);

	// Protocol version 3
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(3), &b).expect("serialization failed");
	assert_eq!(vec.len(), 3_062 + 8 + 8 + 40 + 64);

	// Protocol version 2.
	// Note: block must be in "v2" compatibility with "features and commit" inputs for this.
	// Normally we would convert the block by looking inputs up in utxo but we fake it here for testing.
	let r_sig = Signature::from_raw_data(&[0; 64]).unwrap();
	let static_secp = util::static_secp_instance();
	let static_secp = static_secp.lock();
	let skey1 = SecretKey::from_slice(
		&static_secp,
		&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 1,
		],
	)
	.unwrap();
	let nonce = PublicKey::from_secret_key(&static_secp, &skey1).unwrap();
	let onetime_pubkey = PublicKey::from_secret_key(&static_secp, &skey1).unwrap();
	let view_tag = 0;

	let inputs: Vec<_> = b.inputs().into();
	let inputs: Vec<_> = inputs
		.iter()
		.map(|input| OutputIdentifier {
			features: OutputFeatures::Plain,
			commit: input.commitment(),
			r_sig,
			nonce,
			onetime_pubkey,
			view_tag,
		})
		.collect();
	let b = Block {
		header: b.header,
		// TODO: need to fix hashmap with actual value for this test.
		body: b.body.replace_inputs(
			Inputs::from_output_identifiers(inputs.as_slice(), HashMap::new()).unwrap(),
		),
	};

	// Protocol version 2
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(2), &b).expect("serialization failed");
	assert_eq!(vec.len(), 3_062 + 8 + 8 + 40 + 64);

	// Protocol version 1 (fixed size kernels)
	//let mut vec = Vec::new();
	//this test is no longer valid because v2 is always used
	//ser::serialize(&mut vec, ser::ProtocolVersion(1), &b).expect("serialization failed");
	//assert_eq!(vec.len(), 2_694 + 8 + 40 + 64);

	// Check we can also serialize a v2 compatibility block in v3 protocol version
	// without needing to explicitly convert the block.
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(3), &b).expect("serialization failed");
	assert_eq!(vec.len(), 3_062 + 8 + 8 + 40 + 64);

	// Default protocol version (3) for completeness
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &b).expect("serialization failed");
	assert_eq!(vec.len(), 3_062 + 8 + 8 + 40 + 64);
}

#[test]
fn empty_compact_block_serialized_size() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = b.into();
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &cb).expect("serialization failed");
	assert_eq!(vec.len(), 1_235 + 8 + 8 + 40);
}

#[test]
fn compact_block_single_tx_serialized_size() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let tx1 = tx1i2o();
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = b.into();
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &cb).expect("serialization failed");
	assert_eq!(vec.len(), 1_241 + 8 + 8 + 40);
}

#[test]
fn block_10_tx_serialized_size() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let mut txs = vec![];
	for _ in 0..10 {
		let tx = tx1i2o();
		txs.push(tx);
	}
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&txs, &keychain, &builder, &prev, &key_id);

	{
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &b).expect("serialization failed");
		assert_eq!(vec.len(), 19_577 + 8 + 8 + 40 + 640);
	}
}

#[test]
fn compact_block_10_tx_serialized_size() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let mut txs = vec![];
	for _ in 0..10 {
		let tx = tx1i2o();
		txs.push(tx);
	}
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&txs, &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = b.into();
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &cb).expect("serialization failed");

	assert_eq!(vec.len(), 1_295 + 8 + 8 + 40);
}

#[test]
fn compact_block_hash_with_nonce() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let tx = tx1i2o();
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx.clone()], &keychain, &builder, &prev, &key_id);
	let cb1: CompactBlock = b.clone().into();
	let cb2: CompactBlock = b.clone().into();

	// random nonce will not affect the hash of the compact block itself
	// hash is based on header POW only
	assert!(cb1.nonce != cb2.nonce);
	assert_eq!(b.hash(), cb1.hash());
	assert_eq!(cb1.hash(), cb2.hash());

	assert!(cb1.kern_ids()[0] != cb2.kern_ids()[0]);

	// check we can identify the specified kernel from the short_id
	// correctly in both of the compact_blocks
	assert_eq!(
		cb1.kern_ids()[0],
		tx.kernels()[0].short_id(&cb1.hash(), cb1.nonce)
	);
	assert_eq!(
		cb2.kern_ids()[0],
		tx.kernels()[0].short_id(&cb2.hash(), cb2.nonce)
	);
}

#[test]
fn convert_block_to_compact_block() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let tx1 = tx1i2o();
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = b.clone().into();

	assert_eq!(cb.out_full().len(), 1);
	assert_eq!(cb.kern_full().len(), 1);
	assert_eq!(cb.kern_ids().len(), 1);

	assert_eq!(
		cb.kern_ids()[0],
		b.kernels()
			.iter()
			.find(|x| !x.is_coinbase())
			.unwrap()
			.short_id(&cb.hash(), cb.nonce)
	);
}

#[test]
fn hydrate_empty_compact_block() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = b.clone().into();
	let hb = Block::hydrate_from(cb, &[]).unwrap();
	assert_eq!(hb.header, b.header);
	assert_eq!(hb.outputs(), b.outputs());
	assert_eq!(hb.kernels(), b.kernels());
}

#[test]
fn serialize_deserialize_compact_block() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let tx1 = tx1i2o();
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);

	let mut cb1: CompactBlock = b.into();

	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &cb1).expect("serialization failed");

	// After header serialization, timestamp will lose 'nanos' info, that's the designed behavior.
	// To suppress 'nanos' difference caused assertion fail, we force b.header also lose 'nanos'.
	let origin_ts = cb1.header.timestamp;
	cb1.header.timestamp =
		origin_ts - Duration::nanoseconds(origin_ts.timestamp_subsec_nanos() as i64);

	let cb2: CompactBlock = ser::deserialize_default(&mut &vec[..]).unwrap();

	assert_eq!(cb1.header, cb2.header);
	assert_eq!(cb1.kern_ids(), cb2.kern_ids());
}

// Duplicate a range proof from a valid output into another of the same amount
#[test]
fn same_amount_outputs_copy_range_proof() {
	test_setup();
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let tx = build::transaction(
		KernelFeatures::Plain { fee: 1.into() },
		&[input_rand(7), output_rand(3), output_rand(3)],
		&keychain,
		&builder,
	)
	.unwrap();

	// now we reconstruct the transaction, swapping the rangeproofs so they
	// have the wrong privkey
	let mut outs = tx.outputs().to_vec();
	outs[0].proof = outs[1].proof;

	let key_id = keychain::ExtKeychain::derive_key_id(1, 4, 0, 0, 0);
	let prev = BlockHeader::default();
	let b = new_block(
		&[Transaction::new(tx.inputs(), &outs, tx.kernels())],
		&keychain,
		&builder,
		&prev,
		&key_id,
	);

	// block should have been automatically compacted (including reward
	// output) and should still be valid
	assert_eq!(
		format!(
			"{:?}",
			b.validate(&BlindingFactor::zero(), verifier_cache(), None)
		)
		.contains("InvalidRangeProof"),
		true
	);
}

// Swap a range proof with the right private key but wrong amount
#[test]
fn wrong_amount_range_proof() {
	test_setup();
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let tx1 = build::transaction(
		KernelFeatures::Plain { fee: 1.into() },
		&[input_rand(7), output_rand(3), output_rand(3)],
		&keychain,
		&builder,
	)
	.unwrap();
	let tx2 = build::transaction(
		KernelFeatures::Plain { fee: 1.into() },
		&[input_rand(7), output_rand(2), output_rand(4)],
		&keychain,
		&builder,
	)
	.unwrap();

	// we take the range proofs from tx2 into tx1 and rebuild the transaction
	let mut outs = tx1.outputs().to_vec();
	outs[0].proof = tx2.outputs()[0].proof;
	outs[1].proof = tx2.outputs()[1].proof;

	let key_id = keychain::ExtKeychain::derive_key_id(1, 4, 0, 0, 0);
	let prev = BlockHeader::default();
	let b = new_block(
		&[Transaction::new(tx1.inputs(), &outs, tx1.kernels())],
		&keychain,
		&builder,
		&prev,
		&key_id,
	);

	// block should have been automatically compacted (including reward
	// output) and should still be valid
	assert_eq!(
		format!(
			"{:?}",
			b.validate(&BlindingFactor::zero(), verifier_cache(), None)
		)
		.contains("InvalidRangeProof"),
		true
	);
}

#[test]
fn validate_header_proof() {
	test_setup();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);

	let mut header_buf = vec![];
	{
		let mut writer = ser::BinWriter::default(&mut header_buf);
		b.header.write_pre_pow(&mut writer).unwrap();
		b.header.pow.write_pre_pow(&mut writer).unwrap();
	}
	let pre_pow = header_buf.to_hex();

	let reconstructed = BlockHeader::from_pre_pow_and_proof(
		pre_pow,
		b.header.pow.nonce,
		b.header.pow.proof.clone(),
	)
	.unwrap();
	assert_eq!(reconstructed, b.header);

	// assert invalid pre_pow returns error
	assert!(BlockHeader::from_pre_pow_and_proof(
		"0xaf1678".to_string(),
		b.header.pow.nonce,
		b.header.pow.proof,
	)
	.is_err());
}

// Test coverage for verifying cut-through during block validation.
// It is not valid for a block to spend an output and produce a new output with the same commitment.
// This test covers the case where a output is spent, producing a plain output with the same commitment.
#[test]
fn test_verify_cut_through() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let (address, pri_view) = build::gen_address();

	let (tx_initial, blind_sum) = {
		let out = build::output(consensus::REWARD2, address);
		let in1 = build::input_rand(consensus::REWARD2);
		let tx = Transaction::empty().with_kernel(TxKernel::with_features(KernelFeatures::Plain {
			fee: 0.into(),
		}));

		let (tx, sum) = build::partial_transaction(tx, &[in1, out], &keychain, &builder).unwrap();

		(tx, sum)
	};

	let spending_output = tx_initial.outputs()[0];

	let tx = build::transaction(
		KernelFeatures::Plain { fee: 0.into() },
		&[
			build::initial_tx(tx_initial),
			build::with_excess(blind_sum),
			build::input(consensus::REWARD2, pri_view, spending_output, 1),
			build::output_rand(consensus::REWARD2 - 100),
			build::output_rand(100),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(0, 0, 0, 0, 0);
	let mut block = new_block(&[tx], &keychain, &builder, &prev, &key_id);

	// The block should fail validation due to cut-through.
	assert_eq!(
		format!(
			"{:?}",
			block.validate(&BlindingFactor::zero(), verifier_cache(), None)
		)
		.contains("CutThrough"),
		true,
	);

	// The block should fail lightweight "read" validation due to cut-through.
	assert_eq!(
		format!("{:?}", block.validate_read()).contains("CutThrough"),
		true,
	);

	// Apply cut-through to eliminate the offending input and output.
	let mut inputs: Vec<_> = block.inputs().into();
	let mut outputs = block.outputs().to_vec();
	let (inputs, outputs, _, _) = transaction::cut_through(&mut inputs[..], &mut outputs[..])?;

	block.body = block
		.body
		.replace_inputs(inputs.into())
		.replace_outputs(outputs);

	// Block validates successfully after applying cut-through.
	block.validate(&BlindingFactor::zero(), verifier_cache(), None)?;

	// Block validates via lightweight "read" validation.
	block.validate_read()?;

	Ok(())
}

fn do_btc_kernel_test(
	binary_location: &str,
	signatures: Vec<String>,
	index: u32,
	amount: u64,
	fee: u64,
	redeem_script: Option<&str>,
	expect_valid: bool,
	address_type: u8,
) -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let redeem_script = if redeem_script.is_none() {
		None
	} else {
		let mut data = [0 as u8; 520];
		let redeem_string = redeem_script.unwrap();
		if redeem_string.len() > 520 {
			return Err(Error::Transaction("Invalid BTC Claim".to_string()));
		}
		let data_hex = hex::decode(redeem_string);

		if data_hex.is_err() {
			return Err(Error::Transaction("Invalid BTC Claim".to_string()));
		}

		let mut data_hex = data_hex.unwrap();
		let len = data_hex.len();
		// set no_ops
		data_hex.resize(520, 97);
		data.copy_from_slice(&*data_hex);
		Some(RedeemScript { data, len })
	};

	let keychain = ExtKeychain::from_seed(&[0; 32], true).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let mut utxo_data = UtxoData::new(ChainType::Bypass).unwrap();
	utxo_data.load_binary(binary_location)?;
	let utxo_data = Arc::new(RwLock::new(utxo_data));

	let mut sig_vec = Vec::new();
	let mut rec_id_vec = Vec::new();
	for sig in signatures {
		let signature = base64::decode(sig).unwrap();
		let recid = RecoveryId::from_i32(i32::from((signature[0] - 27) & 3)).unwrap();
		let recsig = RecoverableSignature::from_compact(&signature[1..], recid).unwrap();
		sig_vec.push(recsig);
		rec_id_vec.push(signature[0]);
	}

	let skey = SecretKey::from_slice(
		&keychain.secp(),
		&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 1,
		],
	)
	.unwrap();

	let pub_view = PublicKey::from_secret_key(keychain.secp(), &skey)?;
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let (out, kern) = reward::output_btc_claim(
		&keychain,
		&builder,
		recipient_addr,
		fee,
		true,
		amount,
		index,
		sig_vec,
		rec_id_vec,
		redeem_script,
		address_type,
		Some(skey),
		PaymentId::new(),
	)
	.unwrap();

	let tx = Transaction {
		offset: BlindingFactor::zero(),
		body: TransactionBody {
			inputs: Inputs(Vec::new()),
			outputs: vec![out],
			kernels: vec![kern],
		},
	};

	println!("tx={:?}", tx);

	let b = new_block(&[tx], &keychain, &builder, &prev, &key_id);

	let valid = b.validate(
		&BlindingFactor::zero(),
		verifier_cache(),
		Some(Arc::downgrade(&utxo_data)),
	);

	println!("valid={:?}", valid);
	assert_eq!(valid.is_ok(), expect_valid);
	Ok(())
}

#[test]
// block with a BTCClaim feature
fn test_btc_claim_block() -> Result<(), Error> {
	// test with valid signature
	do_btc_kernel_test(
		"./tests/resources/gen_bin1.bin", // 1AHNUd5zX3ecpjePrWTYNWEbsKX9T1Ephu
		vec!["IBhOFbM5gg+HBTL0tTxgO1a9fTuO+gTuRAyaBJ9jmeLnDFTTii6yINcFeOJ6m2pO/cN12Bg971n5aS5EbUTQs/c=".to_string()],
		0,
		100000000000000,
		100,
		None,
		true,
		0,
	)?;

	// test with invalid signature
	do_btc_kernel_test(
		"./tests/resources/gen_bin1.bin", // 1AHNUd5zX3ecpjePrWTYNWEbsKX9T1Ephu
                vec!["H17AmcEEEEEVa/GUF2IYhgRPmKgtTfvKI+CtIvku4ZEudhIipI0VE8uf7Ixg2PL/6X8a5tT5bFLdU4yfpITkOI8=".to_string()],
                0,
                100000000000000,
                100,
                None,
                false,
		0,
	)?;

	// test with two signatures - should fail
	do_btc_kernel_test(
		"./tests/resources/gen_bin1.bin", // 1AHNUd5zX3ecpjePrWTYNWEbsKX9T1Ephu
                vec![
			"IBhOFbM5gg+HBTL0tTxgO1a9fTuO+gTuRAyaBJ9jmeLnDFTTii6yINcFeOJ6m2pO/cN12Bg971n5aS5EbUTQs/c=".to_string(),
			"IBhOFbM5gg+HBTL0tTxgO1a9fTuO+gTuRAyaBJ9jmeLnDFTTii6yINcFeOJ6m2pO/cN12Bg971n5aS5EbUTQs/c=".to_string()],
                0,
                100000000000000,
                100,
                None,
                false,
		0,
	)?;

	// test with no signatures - should fail
	do_btc_kernel_test(
		"./tests/resources/gen_bin1.bin", // 1AHNUd5zX3ecpjePrWTYNWEbsKX9T1Ephu
		vec![],
		0,
		100000000000000,
		100,
		None,
		false,
		0,
	)?;

	// test with bech32
	do_btc_kernel_test(
                "./tests/resources/gen_bin2.bin", // bc1q6dmqf33rnhxzs5wvgcqhmm43apcpqu2n94l6yk
                vec!["H1bET/AX0Iq3enGE/gVByOa5h/bKLRCvW8rG42+dYifXW9fgs+GzUCEJP1XqaIKdFEsTzH8mB//me5A9QpyuJYg=".to_string()],
                0,
                100000000000000,
                100,
                None,
                true,
		0,
	)?;

	// invalid bech32
	do_btc_kernel_test(
                "./tests/resources/gen_bin2.bin", // bc1q6dmqf33rnhxzs5wvgcqhmm43apcpqu2n94l6yk
                vec!["IAlcDPjjjj6YA2IoDshhjmnlkm0440QJAnH7Lhj+WtDzGjXUE9AXLYxDN7nOz694oMJSKpwsi+YmhXZWEI4FwP4=".to_string()],
                0,
                100000000000000,
                100,
                None,
                false,
		0,
	)?;

	// test with p2shwpkh
	do_btc_kernel_test(
		"./tests/resources/gen_bin3.bin", // 39dd1kqQsJYHtjshwB1LrsekCzWJEGQrfb
		vec!["JAuVo29+ucVIwSQHnoSVW+ZEXVClemYS8HFxTvfxOnV6Sifl3r2EI0A9jp3rcE0rd5ETK9y6eITJBfNHyMykrrQ=".to_string()],
		0,
		100000000000000,
		100,
		None,
		true,
		0,
	)?;

	// invalid p2shwpkh
	do_btc_kernel_test(
                "./tests/resources/gen_bin3.bin", // 39dd1kqQsJYHtjshwB1LrsekCzWJEGQrfb
                vec!["IAlcDPjjjj6YA2IoDshhjmnlkm0440QJAnH7Lhj+WtDzGjXUE9AXLYxDN7nOz694oMJSKpwsi+YmhXZWEI4FwP4=".to_string()],
                0,
                100000000000000,
                100,
                None,
                false,
		0,
        )?;

	// test with multisig (2 of 3)
	do_btc_kernel_test(
		"./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
		vec![
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
			"Hy1ihZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
			"IE6enDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
		],
		0,
		100000000000000,
		100,
		Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
		true,
		util::P2SH,
	)?;

	// test with multisig (2 of 3) two correct, one false
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
                        "Hy1ihZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
                        "IIIInDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
                ],
                0,
                100000000000000,
                100,
                Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
                true,
		util::P2SH,
        )?;

	// test with multisig (2 of 3) two correct, one false different ones
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
                        "HHHHHZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
                        "IE6enDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
                ],
                0,
                100000000000000,
                100,
                Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
                true,
		util::P2SH,
        )?;

	// test with multig (2 of 3) 1 correct, two false
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
                        "HHHHHZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
                        "IEjenDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
                ],
                0,
                100000000000000,
                100,
                Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
                false,
		util::P2SH,
        )?;

	// test with multisig (2 of 3) extra signature (too many will generate error)
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
                        "HHHHHZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
                        "IE6enDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
			"Iljjjjt8hTbhLaFjjjjK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // extra
                ],
                0,
                100000000000000,
                100,
                Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
                false,
		util::P2SH,
        )?;

	// test with p2wsh multisig (2 of 2)
	do_btc_kernel_test(
                "./tests/resources/gen_bin5.bin", // bc1q04npna0ek975eunlanduln2lr8zx2gtyw9rwrk25utkuk96l363sr9qnw6
                vec![
			"IEfPcRyCsV3tNwCFWsVwEdP4bnv13Rtp2+umtFtSsdl1rZSnWiENtozaI/yykO+sBdydouFY1ZguN31PZNywjMo=".to_string(), // p2wsh1
                        "IHbkNPBlZEp915TEvIT+4vafCoVM8o9oSAWpQxHXmzpqf5lDeH3NvKY2ZLE+k2YyuuyfB/znEpSVwlt2W/eMegc=".to_string(), // p2wsh2
                ],
                0,
                100000000000000,
                100,
                Some("522102391e46eb04be749ef3f20f4c2e177902c6fc8ac02e9a2cb13813c2aa418e6c382102bc4cd77f675a17acadca5e\
5d180848ea207237afb87f2b158f86813b4f938dd752ae"),
                true,
		util::P2WSH,
        )?;

	// test with p2wsh multisig (2 of 2) with bad signature
	do_btc_kernel_test(
                "./tests/resources/gen_bin5.bin", // bc1q04npna0ek975eunlanduln2lr8zx2gtyw9rwrk25utkuk96l363sr9qnw6
                vec![
                        "IEfPcRyCsV3tNwCFWsVwEdP4bnv13Rtp2+umtFtSsdl1rZSnWiENtozaI/yykO+sBdydouFY1ZguN31PZNywjMo=".to_string(), // p2wsh1
                        "IHbkjjjjjjp915TEvIT+4vafCoVM8o9oSAWpQxHXmzpqf5lDeH3NvKY2ZLE+k2YyuuyfB/znEpSVwlt2W/eMegc=".to_string(), // p2wsh2
                ],
                0,
                100000000000000,
                100,
                Some("522102391e46eb04be749ef3f20f4c2e177902c6fc8ac02e9a2cb13813c2aa418e6c382102bc4cd77f675a17acadca5e\
5d180848ea207237afb87f2b158f86813b4f938dd752ae"),
                false,
		util::P2WSH,
        )?;

	// test with p2wsh multisig (2 of 2) with extra signature (max signatures is number of pubkeys pushed)
	do_btc_kernel_test(
                "./tests/resources/gen_bin5.bin", // bc1q04npna0ek975eunlanduln2lr8zx2gtyw9rwrk25utkuk96l363sr9qnw6
                vec![
                        "IEfPcRyCsV3tNwCFWsVwEdP4bnv13Rtp2+umtFtSsdl1rZSnWiENtozaI/yykO+sBdydouFY1ZguN31PZNywjMo=".to_string(), // p2wsh1
                        "IHbkNPBlZEp915TEvIT+4vafCoVM8o9oSAWpQxHXmzpqf5lDeH3NvKY2ZLE+k2YyuuyfB/znEpSVwlt2W/eMegc=".to_string(), // p2wsh2
			"IHbkNPBlZEp915TEvIT+4vafCoVM8o9oSAWpQxHXmzpqf5lDeH3NvKY2ZLE+k2YyuuyfB/znEpSVwlt2W/eMegc=".to_string(), // p2wsh2
                ],
                0,
                100000000000000,
                100,
                Some("522102391e46eb04be749ef3f20f4c2e177902c6fc8ac02e9a2cb13813c2aa418e6c382102bc4cd77f675a17acadca5e\
5d180848ea207237afb87f2b158f86813b4f938dd752ae"),
                false,
		util::P2WSH,
        )?;

	Ok(())
}

#[test]
// block with a burn kernel feature
fn test_burn_kernel() {
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	// burn correct amount first
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let max_out = 5;
	let mut pks = vec![];
	for n in 0..(max_out + 1) {
		pks.push(ExtKeychain::derive_key_id(1, n as u32, 0, 0, 0));
	}

	let mut parts = vec![];
	for _ in 0..max_out {
		parts.push(output_rand(5));
	}

	parts.append(&mut vec![input_rand(2 + max_out * 5)]);
	let tx = build::transaction(
		KernelFeatures::Burn {
			fee: 1.into(),
			amount: 1,
		},
		&parts,
		&keychain,
		&builder,
	)
	.unwrap();

	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx], &keychain, &builder, &prev, &key_id);
	assert!(b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_ok());

	// burn wrong amount
	let tx2 = build::transaction(
		KernelFeatures::Burn {
			fee: 1.into(),
			amount: 2,
		},
		&parts,
		&keychain,
		&builder,
	)
	.unwrap();

	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let b = new_block(&[tx2], &keychain, &builder, &prev, &key_id);
	assert!(!b
		.validate(&BlindingFactor::zero(), verifier_cache(), None)
		.is_ok());
}
