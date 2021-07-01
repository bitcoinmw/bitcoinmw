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

//! Transaction integration tests

pub mod common;
use crate::common::tx1i10_v2_compatible;
use crate::core::core::transaction::{self, Error};
use crate::core::core::verifier_cache::{LruVerifierCache, VerifierCache};
use crate::core::core::TransactionBody;
use crate::core::core::{
	FeeFields, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel, Weighting,
};
use crate::core::global;
use crate::core::libtx::proof::{self, ProofBuilder};
use crate::core::libtx::{build, tx_fee};
use crate::core::{consensus, ser};
use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use bmw_utxo::utxo_data::{ChainType, UtxoData};
use grin_core as core;
use grin_core::address::Address;
use grin_core::core::Inputs;
use grin_core::core::RedeemScript;
use grin_core::libtx::proof::PaymentId;
use grin_core::libtx::reward;
use keychain::BlindingFactor;
use keychain::{ExtKeychain, Keychain};
use std::sync::Arc;
use util::secp::key::PublicKey;
use util::secp::key::SecretKey;
use util::secp::Signature;
use util::RwLock;

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

// We use json serialization between wallet->node when pushing transactions to the network.
// This test ensures we exercise this serialization/deserialization code.
#[test]
fn test_transaction_json_ser_deser() {
	let tx1 = tx1i10_v2_compatible();

	let value = serde_json::to_value(&tx1).unwrap();

	println!("{:?}", value);

	assert!(value["offset"].is_string());
	assert!(value["body"]["inputs"][0]["commit"].is_string());
	assert_eq!(value["body"]["outputs"][0]["features"], "Plain");
	assert!(value["body"]["outputs"][0]["commit"].is_string());
	assert!(value["body"]["outputs"][0]["proof"].is_string());

	// Note: Tx kernel "features" serialize in a slightly unexpected way.
	assert_eq!(value["body"]["kernels"][0]["features"]["Plain"]["fee"], 2);
	assert!(value["body"]["kernels"][0]["excess"].is_string());
	assert!(value["body"]["kernels"][0]["excess_sig"].is_string());

	let tx2: Transaction = serde_json::from_value(value).unwrap();
	assert_eq!(tx1, tx2);

	let str = serde_json::to_string(&tx1).unwrap();
	println!("{}", str);
	let tx2: Transaction = serde_json::from_str(&str).unwrap();
	assert_eq!(tx1, tx2);
}

#[test]
fn test_output_ser_deser() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let switch = keychain::SwitchCommitmentType::Regular;
	let commit = keychain.commit(5, &key_id, switch).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let proof = proof::create(&keychain, &builder, 5, &key_id, switch, commit, None).unwrap();

	let skey = SecretKey::from_slice(
		&keychain.secp(),
		&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 1,
		],
	)
	.unwrap();

	let nonce = PublicKey::from_secret_key(&keychain.secp(), &skey).unwrap();
	let onetime_pubkey = PublicKey::from_secret_key(&keychain.secp(), &skey).unwrap();

	let out = Output::new(
		OutputFeatures::Plain,
		commit,
		proof,
		Signature::from_raw_data(&[0; 64]).unwrap(), /* r_sig */
		0,
		nonce,
		onetime_pubkey,
	);

	let mut vec = vec![];
	ser::serialize_default(&mut vec, &out).expect("serialized failed");
	let dout: Output = ser::deserialize_default(&mut &vec[..]).unwrap();

	assert_eq!(dout.features(), OutputFeatures::Plain);
	assert_eq!(dout.commitment(), out.commitment());
	assert_eq!(dout.proof, out.proof);
}

// Test coverage for verifying cut-through during transaction validation.
// It is not valid for a transaction to spend an output and produce a new output with the same commitment.
// This test covers the case where an output is spent, producing an output with the same commitment.
#[test]
fn test_verify_cut_through() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);

	let keychain = ExtKeychain::from_random_seed(false)?;
	let builder = proof::ProofBuilder::new(&keychain);
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

	let mut tx = build::transaction(
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

	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	// Transaction should fail validation due to cut-through.
	let height = 42; // arbitrary
	assert_eq!(
		tx.validate(
			Weighting::AsTransaction,
			verifier_cache.clone(),
			height,
			None,
			None,
		),
		Err(Error::CutThrough),
	);

	// Transaction should fail lightweight "read" validation due to cut-through.
	assert_eq!(tx.validate_read(), Err(Error::CutThrough));

	// Apply cut-through to eliminate the offending input and output.
	let mut inputs: Vec<_> = tx.inputs().into();
	let mut outputs = tx.outputs().to_vec();
	let (inputs, outputs, _, _) = transaction::cut_through(&mut inputs[..], &mut outputs[..])?;

	tx.body = tx
		.body
		.replace_inputs(inputs.into())
		.replace_outputs(outputs);

	// Transaction validates successfully after applying cut-through.
	tx.validate(
		Weighting::AsTransaction,
		verifier_cache.clone(),
		height,
		None,
		None,
	)?;

	// Transaction validates via lightweight "read" validation as well.
	tx.validate_read()?;

	Ok(())
}

// Test coverage for FeeFields
#[test]
fn test_fee_fields() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_accept_fee_base(500_000);

	let keychain = ExtKeychain::from_random_seed(false)?;
	let builder = ProofBuilder::new(&keychain);

	let mut tx = build::transaction(
		KernelFeatures::Plain {
			fee: FeeFields::new(1, 42).unwrap(),
		},
		&[
			build::input_rand(consensus::REWARD3),
			build::output_rand(78_125_000 - 84 - 42 - 21),
		],
		&keychain,
		&builder,
	)
	.expect("valid tx");

	let hf4_height = 4 * consensus::TESTING_HARD_FORK_INTERVAL;
	assert_eq!(
		tx.accept_fee(hf4_height),
		(1 * 1 + 1 * 21 + 1 * 3) * 500_000
	);
	assert_eq!(tx.fee(hf4_height), 42);
	assert_eq!(tx.fee(hf4_height), 42);
	assert_eq!(tx.shifted_fee(hf4_height), 21);

	// activated at launch
	assert_eq!(
		tx.accept_fee(hf4_height - 1),
		(1 * 1 + 1 * 21 + 1 * 3) * 500_000
	);

	//not used anymore
	//assert_eq!(tx.fee(hf4_height - 1), 42 + (1u64 << 40));
	//assert_eq!(tx.shifted_fee(hf4_height - 1), 42 + (1u64 << 40));

	tx.body.kernels.append(&mut vec![
		TxKernel::with_features(KernelFeatures::Plain {
			fee: FeeFields::new(2, 84).unwrap(),
		}),
		TxKernel::with_features(KernelFeatures::Plain { fee: 21.into() }),
	]);

	assert_eq!(tx.fee(hf4_height), 147);
	assert_eq!(tx.shifted_fee(hf4_height), 36);
	assert_eq!(tx.aggregate_fee_fields(hf4_height), FeeFields::new(2, 147));
	assert_eq!(tx_fee(1, 1, 3), 15_500_000);

	Ok(())
}

// Test burn kernels
#[test]
fn test_burn_kernels() -> Result<(), Error> {
	use grin_core::libtx::build;

	global::set_local_chain_type(global::ChainTypes::UserTesting);
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let max_out = 5;
	let mut pks = vec![];
	for n in 0..(max_out + 1) {
		pks.push(ExtKeychain::derive_key_id(1, n as u32, 0, 0, 0));
	}

	let mut parts = vec![];
	for _ in 0..max_out {
		parts.push(build::output_rand(5));
	}

	parts.append(&mut vec![build::input_rand(2 + max_out * 5)]);
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

	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
	let valid = tx.validate(Weighting::AsTransaction, verifier_cache, 0, None, None);

	assert_eq!(valid.is_ok(), true);

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

	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
	let valid = tx2.validate(Weighting::AsTransaction, verifier_cache, 0, None, None);

	assert_eq!(valid.is_ok(), false);
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
			return Err(Error::InvalidBTCClaim);
		}
		let data_hex = hex::decode(redeem_string);

		if data_hex.is_err() {
			return Err(Error::InvalidBTCClaim);
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

	let valid = tx.validate(
		Weighting::AsTransaction,
		verifier_cache(),
		100,
		Some(Arc::downgrade(&utxo_data)),
		None,
	);

	println!("valid={:?}", valid);
	assert_eq!(valid.is_ok(), expect_valid);
	Ok(())
}

#[test]
// block with a BTCClaim feature
fn test_btc_claim_txn() -> Result<(), Error> {
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
                	"IBhOFbM5gg+HBTL0tTxgO1a9fTuO+gTuRAyaBJ9jmeLnDFTTii6yINcFeOJ6m2pO/cN12Bg971n5aS5EbUTQs/c=".to_string()
		],

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
                vec!["H1bBBBAX0Iq3enGE/gVByOa5h/bKLRCvW8rG42+dYifXW9fgs+GzUCEJP1XqaIKdFEsTzH8mB//me5A9QpyuJYg=".to_string()],
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
                vec!["JBBVo20+ucVIwSQHnoSVW+ZEXVClemYS8HFxTvfxOnV6Sifl3r2EI0A9jp3rcE0rd5ETK9y6eITJBfNHyMykrrQ=".to_string()],
                0,
                100000000000000,
                100,
                None,
                false,
		0,
        )?;

	// test with multisig (2 of 3) all sigs valid
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

	// test with multisig (2 of 3) two of three valid, one bad sig (should pass)
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
                        "IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
                        "Hy1ihZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
                        "HyOFBdTP3HZ6WwWZ/1UTJGMneRD4TQev9RWqBTCbuQDZ4hZH5r0fAxHSNQM4YbEFAq3YRJfMmy5PktJone7DyjI=".to_string(), // msig3

                ],
                0,
                100000000000000,
                100,
                Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
                true,
		util::P2SH,
        )?;

	// test with multisig (2 of 3) extra sig fail
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
                        "IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
                        "Hy1ihZMiOJX7SYBmBtDpdiG/7yhXJuG3CmLHF7LnboxlYtwcOqIo1kY0G+7uRjydta5I/hT16qS48NKmt1rqH8g=".to_string(), // msig2
                        "IE6enDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
			"IE6enDsG5kP36AmR7kKh+F47/iCfGKctx3I1bqPKfXM+gMDd+QjRvghFltkW9d3BIAilKs6Wt9g9XSzBvI46px4=".to_string(), // msig3
                ],
                0,
                100000000000000,
                100,
                Some("522102f1bb7bebb1857b32d2e6669507a6a29e70bfc7a3bd70da8a3663a9f51dfce34b21031230211d1d59ef45047c4eaaf12cb026\
c26e308f16af1b3c7c167e52b686ba412103600de4b5d9866f2ae42e1715965e0988d3a35131bbb3eb41c43d505e7a8ebd2253ae"),
                false,
		util::P2SH,
        )?;

	// test with multisig (2 of 3) 1 sig only
	do_btc_kernel_test(
                "./tests/resources/gen_bin4.bin", // 32Uy4DkjqkBUwxhurSgeMZFsKQbM1KP1Hf
                vec![
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
			"IDPJz0t8hTbhLaFtvxmK7sRIX55hw63Amn6RE/hzFpTJJbVUGOHUHufvhYuOgOi8jSHwX1ak2yRqRSmbPPBRFFY=".to_string(), // msig1
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
                        "HyOFBdTP3HZ6WwWZ/1UTJGMneRD4TQev9RWqBTCbuQDZ4hZH5r0fAxHSNQM4YbEFAq3YRJfMmy5PktJone7DyjI=".to_string(), // p2wsh1
                        "H6Rlf//1XNPrOh4jqij3F5fSFtGxq83mhp2h0HjeNjckIP8AHo5IpNOsI+0+S20FpetrCAD+7MZiz/aegqOBe2o=".to_string(), // p2wsh2
                ],
                0,
                100000000000000,
                100,
                Some("522102391e46eb04be749ef3f20f4c2e177902c6fc8ac02e9a2cb13813c2aa418e6c382102bc4cd77f675a17acadca5e\
5d180848ea207237afb87f2b158f86813b4f938dd752ae"),
                false,
		util::P2WSH,
        )?;

	// test with p2wsh multisig (2 of 2) with 1 good one 1 bad sig
	do_btc_kernel_test(
                "./tests/resources/gen_bin5.bin", // bc1q04npna0ek975eunlanduln2lr8zx2gtyw9rwrk25utkuk96l363sr9qnw6
                vec![
                        "IEfPcRyCsV3tNwCFWsVwEdP4bnv13Rtp2+umtFtSsdl1rZSnWiENtozaI/yykO+sBdydouFY1ZguN31PZNywjMo=".to_string(), // p2wsh1
                        "IIBkNPBlZEp915TEvIT+4vafCoVM8o9oSAWpQxHXmzpqf5lDeH3NvKY2ZLE+k2YyuuyfB/znEpSVwlt2W/eMegc=".to_string(), // p2wsh2
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
                        "HyOFBdTP3HZ6WwWZ/1UTJGMneRD4TQev9RWqBTCbuQDZ4hZH5r0fAxHSNQM4YbEFAq3YRJfMmy5PktJone7DyjI=".to_string(), // p2wsh1
                        "H6Rlf//1XNPrOh4jqij3F5fSFtGxq83mhp2h0hjeNjckIP8AHo5IpNOsI+0+S20FpetrCAD+7MZiz/aegqOBe2o=".to_string(), // p2wsh2
			"H6Rlf//1XNPrOh4jqij3F5fSFtGxq83mhp2h0hjeNjckIP8AHo5IpNOsI+0+S20FpetrCAD+7MZiz/aegqOBe2o=".to_string(), // p2wsh2
                ],
                0,
                100000000000000,
                100,
                Some("522102391e46eb04be749ef3f20f4c2e177902c6fc8ac02e9a2cb13813c2aa418e6c382102bc4cd77f675a17acadca5e\
5d180848ea207237afb87f2b158f86813b4f938dd752ae"),
                false,
		util::P2WSH,
        )?;

	// test different fee
	do_btc_kernel_test(
                "./tests/resources/gen_bin6.bin", // bc1qwurv78xc5ymhdxrwcm8mgp7c7rvcd84qya0xf5
                vec!["IBjGPYBvmTnvSx/ZArABDmVIOkWXmycTvcntSDXs/R+rH+Zb/9k3FpvFK5bDZl0yd7nLgBHYxTnnvJUgBgrlyfo=".to_string()],
                0,
                100000000000000,
                101,
                None,
                true,
		0,
        )?;

	// with bad sig
	do_btc_kernel_test(
                "./tests/resources/gen_bin6.bin", // bc1qwurv78xc5ymhdxrwcm8mgp7c7rvcd84qya0xf5
                vec!["IJJgPYBvmTnvSx/ZArABDmVIOkWXmycTvcntSDXs/R+rH+Zb/9k3FpvFK5bDZl0yd7nLgBHYxTnnvJUgBgrlyfo=".to_string()],
                0,
                100000000000000,
                101,
                None,
                false,
                0,
        )?;

	Ok(())
}
