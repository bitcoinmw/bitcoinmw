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

//! Utility functions to build Grin transactions. Handles the blinding of
//! inputs and outputs, maintaining the sum of blinding factors, producing
//! the excess signature, etc.
//!
//! Each building function is a combinator that produces a function taking
//! a transaction a sum of blinding factors, to return another transaction
//! and sum. Combinators can then be chained and executed using the
//! _transaction_ function.
//!
//! Example:
//! build::transaction(
//!   KernelFeatures::Plain{ fee: 2.try_into().unwrap() },
//!   vec![
//!     input_rand(75),
//!     output_rand(42),
//!     output_rand(32),
//!   ]
//! )

use crate::address::Address;
use crate::core::hash::Hash;
use crate::core::hash::Hashed;
use crate::core::CommitWrapper;
use crate::core::OutputIdentifier;
use crate::core::{KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use crate::global;
use crate::libtx::proof::PaymentId;
use crate::libtx::proof::{self, ProofBuild};
use crate::libtx::ErrorKind;
use crate::libtx::ProofBuilder;
use crate::libtx::{aggsig, Error};
use keychain::{BlindSum, BlindingFactor, Keychain, SwitchCommitmentType};
use rand::thread_rng;
use util::secp::key::PublicKey;
use util::secp::key::SecretKey;
use util::secp::Message;
use util::static_secp_instance;

/// Context information available to transaction combinators.
pub struct Context<'a, K, B>
where
	K: Keychain,
	B: ProofBuild,
{
	/// The keychain used for key derivation
	pub keychain: &'a K,
	/// The bulletproof builder
	pub builder: &'a B,
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum) tuple into another, given the provided context.
/// Will return an Err if seomthing went wrong at any point during transaction building.
pub type Append<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	Result<(Transaction, BlindSum), Error>,
) -> Result<(Transaction, BlindSum), Error>;

/// Generate a random address and pri_view tuple
pub fn gen_address() -> (Address, SecretKey) {
	let (pri_view, pub_view) = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let (pri_view, pub_view) = secp.generate_keypair(&mut thread_rng()).unwrap();
		(pri_view, pub_view)
	};

	let recipient_address =
		Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	(recipient_address, pri_view)
}

/// Build an output spendable by the specified recipient_address
pub fn output<K, B>(value: u64, recipient_address: Address) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	let private_nonce = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let (private_nonce, _pub_nonce) = secp.generate_keypair(&mut thread_rng()).unwrap();
		private_nonce
	};
	output_wrnp(value, private_nonce, recipient_address, PaymentId::new())
}

/// Build an input that spends the specified output using the specified secret key
pub fn input<K, B>(
	value: u64,
	pri_view: SecretKey,
	spending_output: Output,
	index: u64,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	let simulated_rp_hash = (index, spending_output.proof).hash();

	let pub_view = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		PublicKey::from_secret_key(&secp, &pri_view).unwrap()
	};
	let recipient_address =
		Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	input_with_sig(
		value,
		pri_view.clone(),
		pri_view,
		spending_output.identifier(),
		recipient_address,
		simulated_rp_hash,
	)
}

/// Builds a random output with specified value (tests only)
pub fn output_rand<K, B>(value: u64) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	let recipient_address = {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let (_pri_view, pub_view) = secp.generate_keypair(&mut thread_rng()).unwrap();
		Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting)
	};

	output(value, recipient_address)
}

/// Builds a random input with specified value (tests only)
pub fn input_rand<K, B>(value: u64) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let (private_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let payment_id = PaymentId::new();
	let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	let spending_output = output_wrnp_impl(
		&keychain,
		&builder,
		value,
		&private_nonce,
		&recipient_addr,
		payment_id,
	)
	.unwrap()
	.0;

	input(value, pri_view, spending_output, 1)
}

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
pub fn input_with_sig<K, B>(
	value: u64,
	private_view_key: SecretKey,
	private_spend_key: SecretKey,
	spending: OutputIdentifier,
	addr: Address,
	rp_hash: Hash,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum), Error> {
			if let Ok((tx, sum)) = acc {
				let switch = SwitchCommitmentType::Regular;
				let input_sig_msg = spending.input_sig_msg(rp_hash);

				let mut a_rr = spending.nonce.clone();
				a_rr.mul_assign(build.keychain.secp(), &private_view_key)?;

				let (ephemeral_key_q, pp_apos, hash_aa_apos) =
					addr.get_ephemeral_key(build.keychain.secp(), &a_rr)?;
				let commit =
					build
						.keychain
						.commit_with_key(value, ephemeral_key_q.clone(), switch)?;
				if pp_apos == spending.onetime_pubkey && commit == spending.commitment() {
					let mut p_apos = hash_aa_apos;
					p_apos.add_assign(build.keychain.secp(), &private_spend_key)?;
					if pp_apos != PublicKey::from_secret_key(build.keychain.secp(), &p_apos)? {
						error!("input_with_sig: one-time public key P' and private p' not match");
						return Err(ErrorKind::Other("incorrect key".to_string()).into());
					}
					let sig = build.keychain.schnorr_sign(&input_sig_msg, &p_apos)?;
					let input = CommitWrapper {
						commit: spending.commitment(),
						sig,
					};

					// Calculate the actual blinding factor for commitment type of SwitchCommitmentType::Regular.
					let blind = match switch {
						SwitchCommitmentType::Regular => {
							build.keychain.secp().blind_switch(value, ephemeral_key_q)?
						}
						SwitchCommitmentType::None => ephemeral_key_q,
					};
					Ok((
						tx.with_input_wsig(input),
						sum.sub_blinding_factor(BlindingFactor::from_secret_key(blind)),
					))
				} else {
					Err(ErrorKind::Other("incorrect key".to_string()).into())
				}
			} else {
				acc
			}
		},
	)
}

/// Build a negative output. This function must not be used outside of tests.
/// The commitment will be an inversion of the value passed in and the value is
/// subtracted from the sum.

pub fn output_negative<K, B>(value: u64, recipient_address: Address) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	use keychain::ExtKeychain;
	use util::secp::Signature;
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum), Error> {
			let (tx, sum) = acc?;

			// TODO: proper support for different switch commitment schemes
			let switch = SwitchCommitmentType::Regular;

			let private_nonce = {
				let secp = static_secp_instance();
				let secp = secp.lock();
				let (private_nonce, _pub_nonce) = secp.generate_keypair(&mut thread_rng()).unwrap();
				private_nonce
			};

			let (ephemeral_key_q, _pp_apos) = recipient_address
				.get_ephemeral_key_for_tx(build.keychain.secp(), &private_nonce)?;
			let commit = build
				.keychain
				.commit_with_key(value, ephemeral_key_q.clone(), switch)?;

			// invert commitment
			let commit = build.keychain.secp().commit_sum(vec![], vec![commit])?;

			debug!("Building output: {}, {:?}", value, commit);

			// build a proof with a rangeproof of 0 as a placeholder
			// the test will replace this later
			let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
			let proof = proof::create(
				build.keychain,
				build.builder,
				0,
				&key_id,
				switch,
				commit,
				None,
			)?;

			// note that these are not valid, but the rangeproof check comes first, and in the test,
			// we assert that the RangeProof error occurs. TODO: cleanup this a bit
			let skey = SecretKey::from_slice(
				&build.keychain.secp(),
				&[
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 1,
				],
			)
			.unwrap();

			let nonce = PublicKey::from_secret_key(&build.keychain.secp(), &skey).unwrap();
			let onetime_pubkey = PublicKey::from_secret_key(&build.keychain.secp(), &skey).unwrap();

			// we return the output and the value is subtracted instead of added
			Ok((
				tx.with_output(Output::new(
					OutputFeatures::Plain,
					commit,
					proof,
					Signature::from_raw_data(&[0; 64]).unwrap(), /* r_sig */
					0,                                           /* view_tag */
					nonce,
					onetime_pubkey,
				)),
				// note that this is also not a valid sum, but as with the skey,
				// the RangeProof check comes first and we assert that error, so this test
				// still works.
				sum.sub_key_id(key_id.to_value_path(value)),
			))
		},
	)
}

/// build and output/blindsum for the specified values
pub fn output_wrnp_impl<K, B>(
	keychain: &K,
	builder: &B,
	value: u64,
	private_nonce: &SecretKey,
	recipient_address: &Address,
	payment_id: PaymentId,
) -> Result<(Output, SecretKey), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let switch = SwitchCommitmentType::Regular;
	let public_nonce = PublicKey::from_secret_key(keychain.secp(), private_nonce)?;

	let (ephemeral_key_q, pp_apos) =
		recipient_address.get_ephemeral_key_for_tx(keychain.secp(), private_nonce)?;
	let view_tag = recipient_address.get_view_tag_for_tx(keychain.secp(), private_nonce)?;
	let commit = keychain.commit_with_key(value, ephemeral_key_q.clone(), switch)?;

	let output_rr_sig_msg = Message::from_slice(
		(
			OutputFeatures::Plain,
			&commit,
			view_tag,
			pp_apos
				.serialize_vec(&keychain.secp(), true)
				.as_ref()
				.to_vec(),
		)
			.hash()
			.to_vec()
			.as_slice(),
	)
	.unwrap();
	let r_sig = keychain.schnorr_sign(&output_rr_sig_msg, private_nonce)?;

	debug!(
		"Building NIT output: {}, {:?} for recipient: {}",
		value,
		commit,
		recipient_address.to_string()
	);

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

	// Calculate the actual blinding factor for commitment type of SwitchCommitmentType::Regular.
	let blind = match switch {
		SwitchCommitmentType::Regular => keychain.secp().blind_switch(value, ephemeral_key_q)?,
		SwitchCommitmentType::None => ephemeral_key_q,
	};

	let output = Output::new(
		OutputFeatures::Plain,
		commit,
		proof,
		r_sig,
		view_tag,
		public_nonce,
		pp_apos,
	);

	Ok((output, blind))
}

/// Adds a NIT output (w/ R&P') with the provided value and key identifier from the keychain.
pub fn output_wrnp<K, B>(
	value: u64,
	private_nonce: SecretKey,
	recipient_address: Address,
	payment_id: PaymentId,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum), Error> {
			let (tx, sum) = acc?;
			let (output, blind) = output_wrnp_impl(
				build.keychain,
				build.builder,
				value,
				&private_nonce,
				&recipient_address,
				payment_id,
			)?;
			Ok((
				tx.with_output(output),
				sum.add_blinding_factor(BlindingFactor::from_secret_key(blind)),
			))
		},
	)
}

/// Adds a known excess value on the transaction being built. Usually used in
/// combination with the initial_tx function when a new transaction is built
/// by adding to a pre-existing one.
pub fn with_excess<K, B>(excess: BlindingFactor) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(Transaction, BlindSum), Error> {
			acc.map(|(tx, sum)| (tx, sum.add_blinding_factor(excess.clone())))
		},
	)
}

/// Sets an initial transaction to add to when building a new transaction.
pub fn initial_tx<K, B>(tx: Transaction) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(Transaction, BlindSum), Error> {
			acc.map(|(_, sum)| (tx.clone(), sum))
		},
	)
}

/// Takes an existing transaction and partially builds on it.
///
/// Example:
/// let (tx, sum) = build::transaction(tx, vec![input_rand(4), output_rand(1))], keychain)?;
///
pub fn partial_transaction<K, B>(
	tx: Transaction,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<(Transaction, BlindingFactor), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, sum) = elems
		.iter()
		.fold(Ok((tx, BlindSum::new())), |acc, elem| elem(&mut ctx, acc))?;
	let blind_sum = ctx.keychain.blind_sum(&sum)?;
	Ok((tx, blind_sum))
}

/// Builds a complete transaction.
/// NOTE: We only use this in tests (for convenience).
/// In the real world we use signature aggregation across multiple participants.
pub fn transaction<K, B>(
	features: KernelFeatures,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut kernel = TxKernel::with_features(features);

	// Construct the message to be signed.
	let msg = kernel.msg_to_sign()?;

	// Generate kernel public excess and associated signature.
	let excess = BlindingFactor::rand(&keychain.secp());
	let skey = excess.secret_key(&keychain.secp())?;
	kernel.excess = keychain.secp().commit(0, skey)?;
	let pubkey = &kernel.excess.to_pubkey(&keychain.secp())?;
	kernel.excess_sig = aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey))?;
	kernel.verify()?;
	transaction_with_kernel(elems, kernel, excess, keychain, builder)
}

/// Build a complete transaction with the provided kernel and corresponding private excess.
/// NOTE: Only used in tests (for convenience).
/// Cannot recommend passing private excess around like this in the real world.
pub fn transaction_with_kernel<K, B>(
	elems: &[Box<Append<K, B>>],
	kernel: TxKernel,
	excess: BlindingFactor,
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, sum) = elems
		.iter()
		.fold(Ok((Transaction::empty(), BlindSum::new())), |acc, elem| {
			elem(&mut ctx, acc)
		})?;
	let blind_sum = ctx.keychain.blind_sum(&sum)?;

	// Update tx with new kernel and offset.
	let mut tx = tx.replace_kernel(kernel);
	tx.offset = blind_sum.split(&excess, &keychain.secp())?;
	Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {
	use std::sync::Arc;
	use util::RwLock;

	use super::*;
	use crate::core::transaction::Weighting;
	use crate::core::verifier_cache::{LruVerifierCache, VerifierCache};
	use crate::global;
	use crate::libtx::ProofBuilder;
	use keychain::ExtKeychain;

	fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
		Arc::new(RwLock::new(LruVerifierCache::new()))
	}

	#[test]
	fn test_simple_nit() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let vc = verifier_cache();

		let (recipient_address, pri_view) = gen_address();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[input_rand(10), output(8, recipient_address)],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(Weighting::AsTransaction, vc.clone(), 37, None, None)
			.unwrap();

		let spending_output = tx.outputs()[0];
		let (recipient_address2, pri_view2) = gen_address();

		let tx2 = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[
				input(8, pri_view, spending_output, 1),
				output(6, recipient_address2),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx2.validate(Weighting::AsTransaction, vc.clone(), 42, None, None)
			.unwrap();

		let spending_output2 = tx2.outputs()[0];

		let tx3 = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[input(6, pri_view2, spending_output2, 1), output_rand(4)],
			&keychain,
			&builder,
		)
		.unwrap();

		tx3.validate(Weighting::AsTransaction, vc.clone(), 43, None, None)
			.unwrap();
	}

	#[test]
	fn blind_simple_tx() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[input_rand(10), input_rand(12), output_rand(20)],
			&keychain,
			&builder,
		)
		.unwrap();

		let height = 42; // arbitrary
		println!("tx={:?}", tx);
		tx.validate(Weighting::AsTransaction, vc.clone(), height, None, None)
			.unwrap();
	}

	#[test]
	fn blind_simple_tx_with_offset() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[input_rand(10), input_rand(12), output_rand(20)],
			&keychain,
			&builder,
		)
		.unwrap();

		let height = 42; // arbitrary
		tx.validate(Weighting::AsTransaction, vc.clone(), height, None, None)
			.unwrap();
	}

	#[test]
	fn blind_simpler_tx() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 4.into() },
			&[input_rand(6), output_rand(2)],
			&keychain,
			&builder,
		)
		.unwrap();

		let height = 42; // arbitrary
		tx.validate(Weighting::AsTransaction, vc.clone(), height, None, None)
			.unwrap();
	}
}
