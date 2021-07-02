# Purpose of gen_log

BitcoinMW is a hard fork of Bitcoin which installs the Bitcoin (BTC) UTXO set into a new, and upgraded application (based on a fork of Grin), which implements the Mimblewimble protocol. The UTXO set from BTC is compressed into a binary that is less than 1 GB. A two step process is used to do this. gen_log is the first step of the two. gen_log reads back the BTC transaction history and logs all transactions to a log file. Then, gen_bin builds the final binary. Checksums of the binary file are stored in the BitcoinMW source code so only one valid binary is possible on the network. To build the gen_bin binary which is valid for testnet, use the height of 671862. On January 3, 2022, at 18:00 UTC, the latest block will be used to build the mainnet snapshot. The checksums of that block will be hard coded into the bitcoinmw source code. Note that building this binary can take a long time (in some cases over a week). An append option is available so mainnet launch will not be delayed.

# Start your bitcoin daemon

./bin/bitcoind -rpcuser=user -rpcpassword=password -txindex -datadir=/path/to/to/bitcoindata &

# Start your gen_log program

./target/release/gen_log user password localhost 8332 ./gen_log.log ./gen_log.err 1 671862
