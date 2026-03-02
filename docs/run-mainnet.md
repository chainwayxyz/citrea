
# Run a Citrea Mainnet Full Node

This guide goes over how to run a full node for Citrea mainnet.

It demonstrates different methods for running required software.


## Bitcoin Mainnet Setup

Citrea mainnet uses Bitcoin mainnet as its DA and settlement layer.

So running a Citrea fullnode requires a fully synced Bitcoin mainnet node.

### Option 1: Build from source

#### Step 1.1: Clone Bitcoin Core Repo


```sh
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
git checkout v30.0
```

#### Step 1.2: Build Bitcoin Core

Then follow the instructions on the links below for the build. However, don't clone the repository since we already did.

OSX: https://github.com/bitcoin/bitcoin/blob/v30.0/doc/build-osx.md

Linux: https://github.com/bitcoin/bitcoin/blob/v30.0/doc/build-unix.md


#### Step 1.3: Run mainnet node:

After the setup, execute these commands to run a Bitcoin mainnet node:

```sh
bitcoind -daemon -txindex=1 -rpcbind=0.0.0.0 -rpcport=8332 -rpcuser=citrea -rpcpassword=citrea
```

You can edit RPC parameters as you wish, but you also have to edit `rollup_config.toml`

### Option 2: Run Docker container

#### Step 2.1: Install Docker

Follow instructions to install Docker here: https://docs.docker.com/engine/install/

#### Step 2.2: Run mainnet node:

After Docker is installed, run this command to pull Bitcoin v0.30.0 image and run it as a container:

```sh
docker run -d \
  -v ${PWD}/bitcoin-mainnet:/home/bitcoin/.bitcoin \
  --name bitcoin-mainnet \
  -p 8332:8332 \
  -p 8333:8333 \
  bitcoin/bitcoin:30.0 \
  -printtoconsole \
  -rest \
  -rpcbind=0.0.0.0 \
  -rpcallowip=0.0.0.0/0 \
  -rpcport=8332 \
  -rpcuser=citrea \
  -rpcpassword=citrea \
  -server \
  -txindex=1
```

You can edit RPC parameters as you wish, but you have to also edit `rollup_config.toml`


## Citrea Full Node Setup

There are three different ways to run a Citrea full node: using a [pre-built binary](#option-1-using-pre-built-binary), [building from source](#option-2-build-from-source) and [using docker](#option-3-using-docker).

### Option 1: Using pre-built binary

Before continuing we suggest creating a `citrea/` directory and executing these commands in that directory.

#### Step 1.1: Download necessary files

Go to this [webpage](https://github.com/chainwayxyz/citrea/releases) and download latest binary for your operating system under "Assets" section.

Run this command to download full node config and mainnet genesis files:
```sh
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/resources/configs/mainnet/rollup_config.toml --output rollup_config.toml
mkdir -p genesis
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/resources/genesis/mainnet/evm.json --output genesis/evm.json
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/resources/genesis/mainnet/accounts.json --output genesis/accounts.json
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/resources/genesis/mainnet/l2_block_rule_enforcer.json --output genesis/l2_block_rule_enforcer.json
```

Look through the `rollup_config.toml` and apply changes as you wish, if you modified any Bitcoin RPC configs, change corresponding values under `[da]`.

#### Step 1.2: Run Citrea Full Node

Finally run this command to run your Citrea full node:

Mac:
```sh
./citrea-v2.1.0-osx-arm64 --network mainnet --da-layer bitcoin --rollup-config-path ./rollup_config.toml --genesis-paths ./genesis
```

or if you wish to use environment variables for configuring your node:

```sh
SEQUENCER_PUBLIC_KEY=03516a66ea4bc3dab67f94dd356edb4eee00a7b33ffe1ab5a1422de5c7c42df4d6 \
SEQUENCER_DA_PUB_KEY=032a31a1fa359abd2e6fc1136b4dea711e5f18618504e021084cc61099f72bb2bd \
PROVER_DA_PUB_KEY=038e501ede61097973e49e714d5f2ad740c82b798bb90fda427fd5138e51f2398e \
NODE_URL=http://0.0.0.0:8332 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
NETWORK=mainnet \
TX_BACKUP_DIR="" \
STORAGE_PATH=resources/dbs \
DB_MAX_OPEN_FILES=5000 \
RPC_BIND_HOST=0.0.0.0 \
RPC_BIND_PORT=8080 \
RPC_MAX_CONNECTIONS=100 \
RPC_MAX_REQUEST_BODY_SIZE=10485760 \
RPC_MAX_RESPONSE_BODY_SIZE=10485760 \
RPC_BATCH_REQUESTS_LIMIT=50 \
RPC_ENABLE_SUBSCRIPTIONS=true \
RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION=10 \
SEQUENCER_CLIENT_URL=https://rpc.mainnet.citrea.xyz \
INCLUDE_TX_BODY=false \
SYNC_BLOCKS_COUNT=10 \
SCAN_L1_START_HEIGHT=924022 \
RUST_LOG=info \
JSON_LOGS=1 \
./citrea-v2.1.0-osx-arm64 --network mainnet --da-layer bitcoin --genesis-paths ./genesis
```

Linux:
```sh
./citrea-v2.1.0-linux-amd64 --network mainnet --da-layer bitcoin --rollup-config-path ./rollup_config.toml --genesis-paths ./genesis
```

or if you wish to use environment variables for configuring your node:


```sh
SEQUENCER_PUBLIC_KEY=03516a66ea4bc3dab67f94dd356edb4eee00a7b33ffe1ab5a1422de5c7c42df4d6 \
SEQUENCER_DA_PUB_KEY=032a31a1fa359abd2e6fc1136b4dea711e5f18618504e021084cc61099f72bb2bd \
PROVER_DA_PUB_KEY=038e501ede61097973e49e714d5f2ad740c82b798bb90fda427fd5138e51f2398e \
NODE_URL=http://0.0.0.0:8332 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
NETWORK=mainnet \
TX_BACKUP_DIR="" \
STORAGE_PATH=resources/dbs \
DB_MAX_OPEN_FILES=5000 \
RPC_BIND_HOST=0.0.0.0 \
RPC_BIND_PORT=8080 \
RPC_MAX_CONNECTIONS=100 \
RPC_MAX_REQUEST_BODY_SIZE=10485760 \
RPC_MAX_RESPONSE_BODY_SIZE=10485760 \
RPC_BATCH_REQUESTS_LIMIT=50 \
RPC_ENABLE_SUBSCRIPTIONS=true \
RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION=10 \
SEQUENCER_CLIENT_URL=https://rpc.mainnet.citrea.xyz \
INCLUDE_TX_BODY=false \
SYNC_BLOCKS_COUNT=10 \
SCAN_L1_START_HEIGHT=924022 \
RUST_LOG=info \
JSON_LOGS=1 \
./citrea-v2.1.0-linux-amd64 --network mainnet --da-layer bitcoin --genesis-paths ./genesis
```

Your full node should be serving RPC at `http://0.0.0.0:8080` now.

### Option 2: Build from source


#### Step 2.1: Install Rust

If you don't have it, install it from [here](https://www.rust-lang.org/tools/install).


#### Step 2.2: Clone the source code

Clone the repository and checkout the latest tag:
```sh
git clone https://github.com/chainwayxyz/citrea
cd citrea
git fetch --tags
git checkout $(git describe --tags `git rev-list --tags --max-count=1`)
```

#### Step 2.3: Build Citrea

Compile Citrea by running command:

```sh
SKIP_GUEST_BUILD=1 cargo build --release
```

Citrea ZK proof circuits are read from `resources/guests`. Rebuilding the circuits are unnecessary if you only wish to run a mainnet node, that's why build is made with `SKIP_GUEST_BUILD=1`.

#### Step 2.4: Run Citrea

Look through the `rollup_config.toml` and apply changes as you wish, if you modified any Bitcoin RPC configs, change corresponding values under `[da]`.

And then run the full node by executing this command

```sh
./target/release/citrea --network mainnet --da-layer bitcoin --rollup-config-path ./resources/configs/mainnet/rollup_config.toml --genesis-paths ./resources/genesis/mainnet
```

If you'd like to use environment variables to pass configs instead of using .toml files you can do so like this:

```sh
SEQUENCER_PUBLIC_KEY=03516a66ea4bc3dab67f94dd356edb4eee00a7b33ffe1ab5a1422de5c7c42df4d6 \
SEQUENCER_DA_PUB_KEY=032a31a1fa359abd2e6fc1136b4dea711e5f18618504e021084cc61099f72bb2bd \
PROVER_DA_PUB_KEY=038e501ede61097973e49e714d5f2ad740c82b798bb90fda427fd5138e51f2398e \
NODE_URL=http://0.0.0.0:8332 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
NETWORK=mainnet \
TX_BACKUP_DIR="" \
STORAGE_PATH=resources/dbs \
DB_MAX_OPEN_FILES=5000 \
RPC_BIND_HOST=0.0.0.0 \
RPC_BIND_PORT=8080 \
RPC_MAX_CONNECTIONS=100 \
RPC_MAX_REQUEST_BODY_SIZE=10485760 \
RPC_MAX_RESPONSE_BODY_SIZE=10485760 \
RPC_BATCH_REQUESTS_LIMIT=50 \
RPC_ENABLE_SUBSCRIPTIONS=true \
RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION=10 \
SEQUENCER_CLIENT_URL=https://rpc.mainnet.citrea.xyz \
INCLUDE_TX_BODY=false \
SYNC_BLOCKS_COUNT=10 \
SCAN_L1_START_HEIGHT=924022 \
RUST_LOG=info \
JSON_LOGS=1 \
./target/release/citrea --network mainnet --da-layer bitcoin --genesis-paths ./resources/genesis/mainnet
```

If you've made any changes to your bitcoin node url, username or password, don't forget to change values for `NODE_URL`, `NODE_USERNAME` and `NODE_PASSWORD`.

### Option 3: Using Docker

Run the full node:
```sh
docker run -d \
  -e NETWORK=mainnet \
  -e NODE_URL=<your_bitcoin_url> \
  -e NODE_USERNAME=<your_username> \
  -e NODE_PASSWORD=<your_password> \
  -v citrea-data:/mnt/task/citrea-db \
  -p 8080:8080 \
  chainwayxyz/citrea-full-node:latest
```

#### Environment Variables

**Required:**
| Variable | Description |
|----------|-------------|
| `NETWORK` | Network to run on: `mainnet` |
| `NODE_URL` | Bitcoin node RPC URL |
| `NODE_USERNAME` | Bitcoin RPC username |
| `NODE_PASSWORD` | Bitcoin RPC password |

**Auto-configured per network (can be overridden):**
| Variable | Description |
|----------|-------------|
| `SEQUENCER_PUBLIC_KEY` | Sequencer's public key |
| `SEQUENCER_DA_PUB_KEY` | Sequencer DA public key |
| `PROVER_DA_PUB_KEY` | Prover DA public key |
| `SCAN_L1_START_HEIGHT` | L1 block height to start syncing |
| `SEQUENCER_CLIENT_URL` | Sequencer RPC URL |
