[![Build Status](https://dev.azure.com/bitcoinmw/bitcoinmw/_apis/build/status/bitcoinmw.bitcoinmw?branchName=master)](https://dev.azure.com/bitcoinmw/bitcoinmw/_apis/build/status/bitcoinmw.bitcoinmw?branchName=master)
[![Documentation Wiki](https://img.shields.io/badge/doc-wiki-blue.svg)](https://github.com/bitcoinmw/docs/wiki)
[![Release Version](https://img.shields.io/github/release/bitcoinmw/bitcoinmw.svg)](https://github.com/bitcoinmw/bitcoinmw/releases)
[![License](https://img.shields.io/github/license/bitcoinmw/bitcoinmw.svg)](https://github.com/bitcoinmw/bitcoinmw/blob/master/LICENSE)

# Bitcoin MW

Bitcoin MW is an implementation of the Mimblewimble protocol that maintains the Bitcoin (BTC) UTXO set with no pre-mine, dev fund, or dev tax. Thus, it is a hard fork of Bitcoin. The Bitcoin UTXO set is installed into an entirely new application which adds privacy, improved scaling, and fungibility characteristics. Whenever there is a fork of Bitcoin, which side of the fork is "Bitcoin" is decided solely in the order book. As developers, we do not make that decision. We only choose which code to maintain. We believe this fork is worthy of our attention and leave it up to the holders of Bitcoin to decide where to assign value.

  * Clean and minimal implementation, and aiming to stay as such.
  * Follows the Mimblewimble protocol, which provides hidden amounts and scaling advantages.
  * Cuckoo Cycle proof of work in two variants named Cuckaroo (ASIC-resistant) and Cuckatoo (ASIC-targeted).
  * Relatively fast block time: one minute.
  * 
  * Transaction fees are based on the number of Outputs created/destroyed and total transaction size.
  * Smooth curve for difficulty adjustments.

To learn more, read our [introduction to Mimblewimble and Grin](doc/intro.md).

## Status

Grin is live with mainnet. Still, much is left to be done and [contributions](CONTRIBUTING.md) are welcome (see below). Check our [mailing list archives](https://lists.launchpad.net/mimblewimble/) for the latest status.

## Contributing

To get involved, read our [contributing docs](CONTRIBUTING.md).

Find us:

* Chat: [Keybase](https://keybase.io/team/grincoin), more instructions on how to join [here](https://grin.mw/community).
* Mailing list: join the [~Mimblewimble team](https://launchpad.net/~mimblewimble) and subscribe on Launchpad.
* Twitter for the Grin council: [@grincouncil](https://twitter.com/grincouncil)

## Getting Started

To learn more about the technology, read our [introduction](doc/intro.md).

To build and try out Grin, see the [build docs](doc/build.md).

## Philosophy

Grin likes itself small and easy on the eyes. It wants to be inclusive and welcoming for all walks of life, without judgement. Grin is terribly ambitious, but not at the detriment of others, rather to further us all. It may have strong opinions to stay in line with its objectives, which doesn't mean disrespect of others' ideas.

We believe in pull requests, data and scientific research. We do not believe in unfounded beliefs.

## Credits

Tom Elvis Jedusor for the first formulation of Mimblewimble.

Andrew Poelstra for his related work and improvements.

John Tromp for the Cuckoo Cycle proof of work.

J.K. Rowling for making it despite extraordinary adversity.

## Motto

Uno Ab Alto.

## License

Apache License v2.0.

