[![Build Status](https://dev.azure.com/bitcoinmw/bitcoinmw/_apis/build/status/bitcoinmw.bitcoinmw?branchName=master)](https://dev.azure.com/bitcoinmw/bitcoinmw/_apis/build/status/bitcoinmw.bitcoinmw?branchName=master)
[![Documentation Wiki](https://img.shields.io/badge/doc-wiki-blue.svg)](https://github.com/bitcoinmw/docs/wiki)
[![Release Version](https://img.shields.io/github/release/bitcoinmw/bitcoinmw.svg)](https://github.com/bitcoinmw/bitcoinmw/releases)
[![License](https://img.shields.io/github/license/bitcoinmw/bitcoinmw.svg)](https://github.com/bitcoinmw/bitcoinmw/blob/master/LICENSE)

# Bitcoin MW

Bitcoin MW is an implementation of the Mimblewimble protocol that maintains the Bitcoin (BTC) UTXO set with no pre-mine, dev fund, ICO or dev tax (i.e. 100% fair launch). Thus, it is a hard fork of Bitcoin. The Bitcoin UTXO set is installed into an entirely new application which adds privacy, improved scaling, and fungibility characteristics. Whenever there is a fork of Bitcoin, which side of the fork is "Bitcoin" is decided solely in the order book. As developers, we do not make that decision. We only choose which code to maintain. We believe this fork is worthy of our attention and leave it up to the holders of Bitcoin to decide where to assign value.

  * Clean and minimal implementation, and aiming to stay as such.
  * Follows the Mimblewimble protocol, which provides hidden amounts and scaling advantages.
  * NIT (Non-interactive transactions) to be more familiar to Bitcoin users.
  * Memory bound, asic-resistant Cuckoo Cycle proof of work (C29d)
  * Relatively fast block time: one minute.
  * Bitcoin's limited supply schedule (starting with the 3.125 coins per 10 minutes epoch) with an extended long tail reward that lasts 1,000 years. Total supply cap is still 21 million.
  * Transaction fees are based on the number of Outputs created/destroyed and total transaction size.
  * Smooth curve for difficulty adjustments.

## Status

BitcoinMW's live with testnet. Launch of mainnet planned for early 2022.

## Contributing

To get involved, read our [contributing docs](CONTRIBUTING.md).

## Getting Started

To build and try out BitcoinMW, see the [build docs](doc/build.md).

## Philosophy

BitcoinMW believes that the BTC utxo set and supply cap is sacrosanct. But, which code users run is open to debate. May the best implementation of Bitcoin win out.

Be the change you wish to see in the world.

## Credits

Tom Elvis Jedusor for the first formulation of Mimblewimble.

Andrew Poelstra for his related work and improvements.

John Tromp for the Cuckoo Cycle proof of work.

Gary Yu for Non-Interactive Transactions.

J.K. Rowling for making it despite extraordinary adversity.

## Motto

Uno Ab Alto.

## License

Apache License v2.0.
