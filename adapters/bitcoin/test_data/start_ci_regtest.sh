# set -e

# BITCOIN_VERSION=0.25.0

# curl -O -L https://bitcoincore.org/bin/bitcoin-core-25.0/bitcoin-25.0-x86_64-linux-gnu.tar.gz
# tar xf bitcoin-25.0-x86_64-linux-gnu.tar.gz

# export PATH=$PATH:./bitcoin-25.0/bin

bitcoind -regtest=1 -daemon=1 -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332
sleep 10
rm -rf /home/chainway/.bitcoin/regtest/wallets/testwallet
sleep 5
bitcoin-cli -regtest=1 -rpcport=38332 -rpcuser=chainway -rpcpassword=topsecret createwallet "testwallet"
sleep 5
bitcoin-cli -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332 -rpcwallet=testwallet324 -generate 250