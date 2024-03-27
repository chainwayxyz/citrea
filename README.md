# Citrea
![](assets/citrea-logo.png)

## Instructions

Clone the repository

```sh
git clone https://github.com/chainwayxyz/citrea.git
```

Build citrea:
```sh
SKIP_GUEST_BUILD=1 make build
```

### Run on Mock DA
Run on a local da layer, sharable between nodes that run on your computer.

Run sequencer on Mock DA:
```sh
./target/debug/citrea --da-layer mock --rollup-config-path citrea/rollup/configs/mock/sequencer_rollup_config.toml --sequencer-config-path citrea/rollup/configs/mock/sequencer_config.toml --genesis-paths citrea/test-data/genesis/demo-tests/mock
```

Sequencer RPC is accessible at `127.0.0.1:12345`

_Optional_: Run full node on Mock DA:
```sh
./target/debug/citrea --rollup-config-path citrea/rollup/configs/mock/rollup_config.toml --genesis-paths citrea/test-data/genesis/demo-tests/mock 
```

Full node RPC is accessible at `127.0.0.1:12346`

To publish blocks on Mock DA, run these on two seperate terminals:
```sh
 ./citrea/rollup/publish_block.sh

 ./citrea/rollup/publish_da_block.sh
```

### Run on Bitcoin Regtest

Run on local Bitcoin network.

Run Bitcoin Regtest:
```sh
bitcoind -regtest -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332 -txindex=1
```
Keep this terminal open.

Create bitcoin wallet for Bitcoin DA adapter.
```sh
bitcoin-cli -regtest  -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332 createwallet citreatesting
bitcoin-cli -regtest  -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332 loadwallet citreatesting
```

Mine blocks so that the wallet has BTC:
```sh
bitcoin-cli -regtest  -rpcuser=chainway -rpcpassword=topsecret -rpcport=38332 -generate 201
```

Run sequencer:
```sh
./target/debug/citrea --da-layer bitcoin --rollup-config-path citrea/rollup/configs/bitcoin-regtest/sequencer_rollup_config.toml --sequencer-config-path citrea/rollup/configs/bitcoin-regtest/sequencer_config.toml --genesis-paths citrea/test-data/genesis/demo-tests/bitcoin-regtest
```

Sequencer RPC is accessible at `127.0.0.1:12345`

_Optional_: Run full node

Run full node:
```sh
./target/debug/citrea --da-layer bitcoin --rollup-config-path citrea/rollup/configs/bitcoin-regtest/rollup_config.toml --genesis-paths citrea/test-data/genesis/demo-tests/bitcoin-regtest
```

Full node RPC is accessible at `127.0.0.1:12346`

To publish blocks on Bitcoin Regtest, run this and keep the terminal open:
```sh
 ./citrea/rollup/publish_block.sh
```
