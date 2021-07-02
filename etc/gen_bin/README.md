# Purpose of gen_bin

BitcoinMW is a hard fork of Bitcoin which installs the Bitcoin (BTC) UTXO set into a new, and upgraded application (based on a fork of Grin), which implements the Mimblewimble protocol. The UTXO set from BTC is compressed into a binary that is less than 1 GB. A two step process is used to do this. gen_bin is the second step of the two. gen_log reads the btc transaction history and logs all transactions to a log file. Then, gen_bin builds the final binary. Checksums of the binary file are stored in the BitcoinMW source code so only one valid binary is possible on the network. To build the gen_bin binary which is valid for testnet, use the height of 671862. On January 3, 2022, at 18:00 UTC, the latest block will be used to build the mainnet snapshot. The checksums of that block will be hard coded into the bitcoinmw source code. Note that building this binary can take a long time (in some cases over a week). An append option is available so mainnet launch will not be delayed.


# Start your gen_bin program

Note: you will need at least 16 GB of RAM (preferably 32 GB) to build gen_bin. It should take around 12-24 hours to complete.

./target/release/gen_bin location_of_gen_log.log gen_bin.bin

# Installing gen_bin into bitcoinmw

Copy the gen_bin binary into your chain_data directory (e.g. cp gen_bin.bin ~/.bmw/test/chain_data). Please note that most users will not need to do this as it is automatically downloaded from other hosts that have the binary on startup of bitcoinmw.
