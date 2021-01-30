// Copyright 2020 The Grin Developers
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

use grin_core::consensus::{
	header_version, secondary_pow_ratio, HARD_FORK_INTERVAL, TESTNET_FIRST_HARD_FORK,
	TESTNET_FOURTH_HARD_FORK, TESTNET_SECOND_HARD_FORK, TESTNET_THIRD_HARD_FORK,
};
use grin_core::core::HeaderVersion;
use grin_core::global;

#[test]
fn test_secondary_pow_ratio() {
	// Tests for Testnet chain type (covers pre and post hardfork).
	global::set_local_chain_type(global::ChainTypes::Testnet);
	assert_eq!(global::is_testnet(), true);

	assert_eq!(secondary_pow_ratio(1), 100);
	assert_eq!(secondary_pow_ratio(89), 100);
	assert_eq!(secondary_pow_ratio(90), 100);
	assert_eq!(secondary_pow_ratio(91), 100);
	assert_eq!(secondary_pow_ratio(179), 100);
	assert_eq!(secondary_pow_ratio(180), 100);
	assert_eq!(secondary_pow_ratio(181), 100);

	let one_week = 60 * 24 * 7;
	assert_eq!(secondary_pow_ratio(one_week - 1), 100);
	assert_eq!(secondary_pow_ratio(one_week), 100);
	assert_eq!(secondary_pow_ratio(one_week + 1), 100);

	let two_weeks = one_week * 2;
	assert_eq!(secondary_pow_ratio(two_weeks - 1), 100);
	assert_eq!(secondary_pow_ratio(two_weeks), 100);
	assert_eq!(secondary_pow_ratio(two_weeks + 1), 100);

	let t4_fork_height = 64_000;
	assert_eq!(secondary_pow_ratio(t4_fork_height - 1), 100);
	assert_eq!(secondary_pow_ratio(t4_fork_height), 100);
	assert_eq!(secondary_pow_ratio(t4_fork_height + 1), 100);

	let one_year = one_week * 52;
	assert_eq!(secondary_pow_ratio(one_year), 100);

	let ninety_one_weeks = one_week * 91;
	assert_eq!(secondary_pow_ratio(ninety_one_weeks - 1), 100);
	assert_eq!(secondary_pow_ratio(ninety_one_weeks), 100);
	assert_eq!(secondary_pow_ratio(ninety_one_weeks + 1), 100);

	let two_year = one_year * 2;
	assert_eq!(secondary_pow_ratio(two_year - 1), 100);
	assert_eq!(secondary_pow_ratio(two_year), 100);
	assert_eq!(secondary_pow_ratio(two_year + 1), 100);
}

#[test]
fn hard_forks() {
	global::set_local_chain_type(global::ChainTypes::Testnet);
	assert_eq!(global::is_testnet(), true);
	assert_eq!(header_version(0), HeaderVersion(1));
	assert_eq!(header_version(10), HeaderVersion(1));

	assert_eq!(
		header_version(TESTNET_FIRST_HARD_FORK - 1),
		HeaderVersion(1)
	);
	assert_eq!(header_version(TESTNET_FIRST_HARD_FORK), HeaderVersion(1));
	assert_eq!(
		header_version(TESTNET_FIRST_HARD_FORK + 1),
		HeaderVersion(1)
	);

	assert_eq!(
		header_version(TESTNET_SECOND_HARD_FORK - 1),
		HeaderVersion(1)
	);
	assert_eq!(header_version(TESTNET_SECOND_HARD_FORK), HeaderVersion(1));
	assert_eq!(
		header_version(TESTNET_SECOND_HARD_FORK + 1),
		HeaderVersion(1)
	);

	assert_eq!(
		header_version(TESTNET_THIRD_HARD_FORK - 1),
		HeaderVersion(1)
	);
	assert_eq!(header_version(TESTNET_THIRD_HARD_FORK), HeaderVersion(1));
	assert_eq!(
		header_version(TESTNET_THIRD_HARD_FORK + 1),
		HeaderVersion(1)
	);

	assert_eq!(
		header_version(TESTNET_FOURTH_HARD_FORK - 1),
		HeaderVersion(1)
	);
	assert_eq!(header_version(TESTNET_FOURTH_HARD_FORK), HeaderVersion(1));
	assert_eq!(
		header_version(TESTNET_FOURTH_HARD_FORK + 1),
		HeaderVersion(1)
	);

	assert_eq!(header_version(HARD_FORK_INTERVAL - 1), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL + 1), HeaderVersion(1));

	assert_eq!(header_version(HARD_FORK_INTERVAL * 2 - 1), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL * 2), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL * 2 + 1), HeaderVersion(1));

	assert_eq!(header_version(HARD_FORK_INTERVAL * 3 - 1), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL * 3), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL * 3 + 1), HeaderVersion(1));

	assert_eq!(header_version(HARD_FORK_INTERVAL * 4 - 1), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL * 4), HeaderVersion(1));
	assert_eq!(header_version(HARD_FORK_INTERVAL * 4 + 1), HeaderVersion(1));
}
