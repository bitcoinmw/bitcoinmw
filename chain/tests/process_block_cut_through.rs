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

mod chain_test_helper;

use grin_chain as chain;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;

use self::chain_test_helper::{build_block, clean_output_dir, genesis_block, init_chain};
use crate::chain::{pipe, Options};
use crate::core::core::verifier_cache::LruVerifierCache;
use crate::core::core::{FeeFields, KernelFeatures, Weighting};
use crate::core::libtx::{build, ProofBuilder};
use crate::core::{consensus, global};
use crate::keychain::{ExtKeychain, Keychain};
use crate::util::RwLock;
use grin_core::address::Address;
use grin_core::libtx::proof::PaymentId;
use rand::thread_rng;
use std::sync::Arc;

#[test]
fn process_block_cut_through() -> Result<(), chain::Error> {
	let chain_dir = ".bmw.cut_through";
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	util::init_test_logger();
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false)?;
	let pb = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());
	let mut pri_views = vec![];
	let mut outputs = vec![];
	let mut pri_nonces = vec![];
	let mut recipient_addrs = vec![];

	// Mine a few empty blocks.
	for _ in 1..6 {
		let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		pri_views.push(pri_view);
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		recipient_addrs.push(recipient_addr.clone());
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		pri_nonces.push(private_nonce.clone());
		let block = build_block(
			&chain,
			&keychain,
			(&[]).to_vec(),
			recipient_addr,
			private_nonce,
			true,
		);
		outputs.push(block.outputs()[0]);
		chain.process_block(block.clone(), Options::MINE)?;
	}

	let index0: u64 = chain.get_output_pos(&outputs[0].commitment()).unwrap() - 1;
	let index1: u64 = chain.get_output_pos(&outputs[1].commitment()).unwrap() - 1;

	// Build a tx that spends a couple of early coinbase outputs and produces some new outputs.
	// Note: We reuse key_ids resulting in an input and an output sharing the same commitment.
	// The input is coinbase and the output is plain.
	let tx = build::transaction(
		KernelFeatures::Plain {
			fee: FeeFields::zero(),
		},
		&[
			build::input(consensus::REWARD1, pri_views[0].clone(), outputs[0], index0),
			build::input(consensus::REWARD1, pri_views[1].clone(), outputs[1], index1),
			build::output_wrnp(
				consensus::REWARD1,
				pri_nonces[0].clone(),
				recipient_addrs[0].clone(),
				PaymentId::new(),
			),
			build::output_rand(212_500_000),
			build::output_rand(100_000_000),
		],
		&keychain,
		&pb,
	)
	.expect("valid tx");

	// The offending commitment, reused in both an input and an output.
	let commit = build::output_wrnp_impl(
		&keychain,
		&pb,
		consensus::REWARD1,
		&pri_nonces[0].clone(),
		&recipient_addrs[0].clone(),
		PaymentId::new(),
	)
	.unwrap()
	.0
	.identifier
	.commit;
	let inputs: Vec<_> = tx.inputs().into();
	assert!(inputs.iter().any(|input| input.commitment() == commit));
	assert!(tx
		.outputs()
		.iter()
		.any(|output| output.commitment() == commit));

	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

	// Transaction is invalid due to cut-through.
	let height = 7;
	match tx.validate(
		Weighting::AsTransaction,
		verifier_cache.clone(),
		height,
		None,
		None,
	) {
		Ok(_) => panic!("should not be valid"),
		Err(e) => {
			assert_eq!(format!("{:?}", e).contains("CutThrough"), true);
		}
	}

	// Transaction will not validate against the chain (utxo).
	assert_eq!(
		chain.validate_tx(&tx).map_err(|e| e.kind()),
		Err(chain::ErrorKind::DuplicateCommitment(commit)),
	);

	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	let (private_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	// Build a block with this single invalid transaction.
	let block = build_block(
		&chain,
		&keychain,
		(&[tx.clone()]).to_vec(),
		recipient_addr,
		private_nonce,
		false,
	);

	// The block is invalid due to cut-through.
	let prev = chain.head_header()?;
	assert_eq!(
		format!(
			"{:?}",
			block.validate(&prev.total_kernel_offset(), verifier_cache.clone(), None)
		)
		.contains("CutThrough"),
		true
	);

	// The block processing pipeline will refuse to accept the block due to "duplicate commitment".
	// Note: The error is "Other" with a stringified backtrace and is effectively impossible to introspect here...
	assert!(chain.process_block(block.clone(), Options::MINE).is_err());

	// Now exercise the internal call to pipe::process_block() directly so we can introspect the error
	// without it being wrapped as above.
	{
		let store = chain.store();
		let header_pmmr = chain.header_pmmr();
		let txhashset = chain.txhashset();

		let mut header_pmmr = header_pmmr.write();
		let mut txhashset = txhashset.write();
		let batch = store.batch()?;

		let mut ctx = chain.new_ctx(Options::NONE, batch, &mut header_pmmr, &mut txhashset)?;
		let res = pipe::process_block(&block, &mut ctx, None).map_err(|e| e.kind());
		assert_eq!(res.is_err(), true);
		assert_eq!(format!("{:?}", res).contains("CutThrough"), true);
	}

	clean_output_dir(chain_dir);
	Ok(())
}
