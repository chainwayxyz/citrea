set -e

bitcoind -regtest=1 -daemon=1 -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332
sleep 10
bitcoin-cli -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332 -rpcwallet=testwallet -generate 250