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

//! Common test functions

use grin_core::address::Address;
use grin_core::core::hash::DefaultHashable;
use grin_core::core::Inputs;
use grin_core::core::Output;
use grin_core::core::{
	Block, BlockHeader, KernelFeatures, OutputFeatures, OutputIdentifier, Transaction,
};
use grin_core::global;
use grin_core::libtx::build::input;
use grin_core::libtx::build::{input_rand, output_rand};
use grin_core::libtx::proof::PaymentId;
use grin_core::libtx::{
	build::{self},
	proof::{ProofBuild, ProofBuilder},
	reward,
};
use grin_core::pow::Difficulty;
use grin_core::ser::{self, PMMRable, Readable, Reader, Writeable, Writer};
use keychain::{Identifier, Keychain};
use rand::thread_rng;
use std::collections::HashMap;
use util::secp::key::{PublicKey, SecretKey};
use util::secp::Signature;

// utility producing a transaction with 2 inputs and a single outputs
#[allow(dead_code)]
pub fn tx2i1o() -> Transaction {
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let tx = build::transaction(
		KernelFeatures::Plain { fee: 2.into() },
		&[input_rand(10), input_rand(11), output_rand(19)],
		&keychain,
		&builder,
	)
	.unwrap();

	tx
}

// utility producing a transaction with a single input and output
#[allow(dead_code)]
pub fn tx1i1o() -> Transaction {
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let tx = build::transaction(
		KernelFeatures::Plain { fee: 2.into() },
		&[input_rand(5), output_rand(3)],
		&keychain,
		&builder,
	)
	.unwrap();

	tx
}

#[allow(dead_code)]
pub fn tx1i10_v2_compatible() -> Transaction {
	let tx = tx1i1o();

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

	let inputs: Vec<_> = tx.inputs().into();
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
	Transaction {
		// TODO: need to update
		body: tx.body.replace_inputs(
			Inputs::from_output_identifiers(inputs.as_slice(), HashMap::new()).unwrap(),
		),
		..tx
	}
}

// utility producing a transaction with a single input
// and two outputs (one change output)
// Note: this tx has an "offset" kernel
#[allow(dead_code)]
pub fn tx1i2o() -> Transaction {
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);

	let tx = build::transaction(
		KernelFeatures::Plain { fee: 2.into() },
		&[input_rand(6), output_rand(3), output_rand(1)],
		&keychain,
		&builder,
	)
	.unwrap();

	tx
}

// utility to create a block without worrying about the key or previous
// header
// TODO: change from key_id to recipient_address
#[allow(dead_code)]
pub fn new_block<K, B>(
	txs: &[Transaction],
	keychain: &K,
	builder: &B,
	previous_header: &BlockHeader,
	_key_id: &Identifier,
) -> Block
where
	K: Keychain,
	B: ProofBuild,
{
	let fees = txs
		.iter()
		.map(|tx| tx.fee(previous_header.height + 1))
		.sum();

	let (private_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let payment_id = PaymentId::new();
	let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);

	let reward_output = reward::nit_output(
		keychain,
		builder,
		private_nonce,
		recipient_addr.clone(),
		payment_id,
		fees,
		false,
		1,
	)
	.unwrap();

	Block::new(
		&previous_header,
		txs,
		Difficulty::min_dma(),
		reward_output,
		None,
	)
	.unwrap()
}

// utility producing a transaction that spends an output with the provided
// value and blinding key
#[allow(dead_code)]
pub fn txspend1i1o<K, B>(
	v: u64,
	keychain: &K,
	builder: &B,
	spending_output: Output,
	pri_view: SecretKey,
) -> Transaction
where
	K: Keychain,
	B: ProofBuild,
{
	build::transaction(
		KernelFeatures::Plain { fee: 2.into() },
		&[input(v, pri_view, spending_output, 1), output_rand(3)],
		keychain,
		builder,
	)
	.unwrap()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TestElem(pub [u32; 4]);

impl DefaultHashable for TestElem {}

impl PMMRable for TestElem {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		*self
	}

	fn elmt_size() -> Option<u16> {
		Some(16)
	}
}

impl Writeable for TestElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.0[0])?;
		writer.write_u32(self.0[1])?;
		writer.write_u32(self.0[2])?;
		writer.write_u32(self.0[3])
	}
}

impl Readable for TestElem {
	fn read<R: Reader>(reader: &mut R) -> Result<TestElem, ser::Error> {
		Ok(TestElem([
			reader.read_u32()?,
			reader.read_u32()?,
			reader.read_u32()?,
			reader.read_u32()?,
		]))
	}
}
