# Start your bitcoin daemon

./bin/bitcoind -rpcuser=user -rpcpassword=password -txindex -datadir=/path/to/to/bitcoindata &

# Start your gen_log program

./target/release/gen_log user password localhost 8332 ./gen_log.log ./gen_log.err 1 673000
