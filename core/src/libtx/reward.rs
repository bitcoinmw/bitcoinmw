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

//! Builds the blinded output and related signature proof for the block
//! reward.

use crate::address::Address;
use crate::consensus::reward;
use crate::core::build_btc_init_kernel_feature;
use crate::core::hash::Hashed;
use crate::core::FeeFields;
use crate::core::RedeemScript;
use crate::core::{KernelFeatures, NotarizationData, Output, OutputFeatures, TxKernel};
use crate::libtx::build;
use crate::libtx::error::Error;
use crate::libtx::proof::PaymentId;
use crate::libtx::{
	aggsig,
	proof::{self, ProofBuild},
};
use bitcoin::secp256k1::recovery::RecoverableSignature;
use keychain::{Keychain, SwitchCommitmentType};
use rand::thread_rng;
use util::secp::key::PublicKey;
use util::secp::key::SecretKey;

/// Output a BTC claim

pub fn output_btc_claim<K, B>(
	keychain: &K,
	builder: &B,
	recipient_address: Address,
	fee: u64,
	test_mode: bool,
	amount: u64,
	index: u32,
	btc_sigs: Vec<RecoverableSignature>,
	btc_recovery_bytes: Vec<u8>,
	redeem_script: Option<RedeemScript>,
	address_type: u8,
	private_nonce: Option<SecretKey>,
	payment_id: PaymentId,
) -> Result<(Output, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let ff = if fee == 0 {
		FeeFields::zero()
	} else {
		FeeFields::new(0, fee)?
	};
	let kernel_features = build_btc_init_kernel_feature(
		ff,
		index,
		btc_sigs,
		btc_recovery_bytes,
		redeem_script,
		address_type,
	)?;
	output_impl(
		keychain,
		builder,
		recipient_address,
		test_mode,
		amount - fee,
		kernel_features,
		OutputFeatures::Plain,
		private_nonce,
		payment_id,
	)
}

/// Output a reward
/*
pub fn output<K, B>(
	keychain: &K,
	builder: &B,
	key_id: &Identifier,
	fees: u64,
	test_mode: bool,
	height: u64,
) -> Result<(Output, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let value = reward(fees, height);
	let (private_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	output_impl(
		keychain,
		builder,
		key_id,
		test_mode,
		value,
		KernelFeatures::Coinbase {
			notarization_data: NotarizationData { data: [0; 40] },
		},
		OutputFeatures::Coinbase,
	)
}
*/

/// output a reward or BTCCLaim output

pub fn output_impl<K, B>(
	keychain: &K,
	builder: &B,
	recipient_address: Address,
	test_mode: bool,
	value: u64,
	features: KernelFeatures,
	_output_features: OutputFeatures,
	private_nonce: Option<SecretKey>,
	payment_id: PaymentId,
) -> Result<(Output, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let private_nonce = if private_nonce.is_some() {
		private_nonce.unwrap()
	} else {
		let (private_nonce, _pub_nonce) =
			keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		private_nonce
	};
	let (output, blind) = build::output_wrnp_impl(
		keychain,
		builder,
		value,
		&private_nonce.clone(),
		&recipient_address,
		payment_id,
	)?;

	let secp = keychain.secp();
	let over_commit = secp.commit_value(value)?;
	let out_commit = output.commitment();
	let excess = secp.commit_sum(vec![out_commit], vec![over_commit])?;
	let pubkey = excess.to_pubkey(&secp)?;

	let msg = features.kernel_sig_msg()?;
	let sig = match test_mode {
		true => {
			let test_nonce = util::secp::key::SecretKey::from_slice(&secp, &[1; 32])?;
			aggsig::sign_single(&secp, &msg, &blind, Some(&test_nonce), Some(&pubkey))?

			/*
			pub fn sign_single(
					secp: &Secp256k1,
					msg: &Message,
					skey: &SecretKey,
					snonce: Option<&SecretKey>,
					pubkey_sum: Option<&PublicKey>,
			) -> Result<Signature, Error> {
			*/
			/*
						aggsig::sign_from_key_id(
							&secp,
							keychain,
							&msg,
							value,
							&key_id,
							Some(&test_nonce),
							Some(&pubkey),
						)?
			*/
		}
		false => {
			//aggsig::sign_from_key_id(&secp, keychain, &msg, value, &key_id, None, Some(&pubkey))?
			aggsig::sign_single(&secp, &msg, &blind, None, Some(&pubkey))?
		}
	};

	let kernel = TxKernel {
		features,
		excess,
		excess_sig: sig,
	};
	Ok((output, kernel))
}

/// create a reward output to a receiver address (reward with non-interactive transaction style)
pub fn nit_output<K, B>(
	keychain: &K,
	builder: &B,
	private_nonce: SecretKey,
	recipient_address: Address,
	payment_id: PaymentId,
	fees: u64,
	test_mode: bool,
	height: u64,
) -> Result<(Output, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let value = reward(fees, height);
	let switch = SwitchCommitmentType::Regular;
	let nonce = PublicKey::from_secret_key(keychain.secp(), &private_nonce)?;
	let (ephemeral_key_q, onetime_pubkey) =
		recipient_address.get_ephemeral_key_for_tx(keychain.secp(), &private_nonce)?;
	let view_tag = recipient_address.get_view_tag_for_tx(keychain.secp(), &private_nonce)?;
	let commit = keychain.commit_with_key(value, ephemeral_key_q.clone(), switch)?;

	trace!("Block reward - Pedersen Commit is: {:?}", commit,);

	let output_rr_sig_msg = util::secp::Message::from_slice(
		(
			OutputFeatures::Coinbase,
			&commit,
			view_tag,
			onetime_pubkey
				.serialize_vec(keychain.secp(), true)
				.as_ref()
				.to_vec(),
		)
			.hash()
			.to_vec()
			.as_slice(),
	)
	.unwrap();
	let r_sig = keychain.schnorr_sign(&output_rr_sig_msg, &private_nonce)?;

	let proof = proof::nit_create(
		keychain,
		builder,
		value,
		ephemeral_key_q.clone(),
		switch,
		commit,
		payment_id,
		None,
	)?;

	let output = Output::new(
		OutputFeatures::Coinbase,
		commit,
		proof,
		r_sig,
		view_tag,
		nonce,
		onetime_pubkey,
	);

	let over_commit = keychain.secp().commit_value(value)?;
	let out_commit = output.commitment();
	let excess =
		util::secp::Secp256k1::commit_sum(keychain.secp(), vec![out_commit], vec![over_commit])?;
	let pubkey = excess.to_pubkey(keychain.secp())?;

	let features = KernelFeatures::Coinbase {
		notarization_data: NotarizationData { data: [0; 40] },
	};
	let msg = features.kernel_sig_msg()?;
	// Calculate the actual blinding factor for commitment type of SwitchCommitmentType::Regular.
	let blind = match switch {
		SwitchCommitmentType::Regular => keychain.secp().blind_switch(value, ephemeral_key_q)?,
		SwitchCommitmentType::None => ephemeral_key_q,
	};
	let sig = match test_mode {
		true => {
			let test_nonce = util::secp::key::SecretKey::from_slice(keychain.secp(), &[1; 32])?;
			aggsig::sign_single(
				keychain.secp(),
				&msg,
				&blind,
				Some(&test_nonce),
				Some(&pubkey),
			)?
		}
		false => aggsig::sign_single(keychain.secp(), &msg, &blind, None, Some(&pubkey))?,
	};

	let kernel = TxKernel {
		features,
		excess,
		excess_sig: sig,
	};
	Ok((output, kernel))
}
