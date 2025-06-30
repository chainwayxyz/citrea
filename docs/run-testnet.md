
## TL; DR: I want to run it ASAP
Download our testnet docker-compose file:

```sh
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/docker/docker-compose.yml --output docker-compose.yml
```

Then use `docker-compose` to both launch a Bitcoin testnet4 node and Citrea full node:
```sh
docker-compose -f docker/docker-compose.yml up
```

# Run a Citrea Testnet Full Node

This guide goes over how to run a full node for Citrea testnet.

It demonstrates different methods for running required software.


## Bitcoin Testnet Setup

Citrea testnet uses Bitcoin testnet4 as its DA and settlement layer.

So running a Citrea fullnode requires a fully synced Bitcoin testnet4 node.

Testnet4 is only enabled in versions bigger than 28.0.

### Option 1: Build from source

#### Step 1.1: Clone Bitcoin Core Repo


```sh
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
git checkout v28.0
```

#### Step 1.2: Build Bitcoin Core

Then follow the instructions on the links below for the build. However, don't clone the repository since we already did.

OSX: https://github.com/bitcoin/bitcoin/blob/v28.0/doc/build-osx.md

Linux: https://github.com/bitcoin/bitcoin/blob/v28.0/doc/build-unix.md


#### Step 1.3: Run testnet4 node:

After the setup, execute these commands to run a Bitcoin testnet4 node:

```sh
bitcoind -testnet4 -daemon -txindex=1 -rpcbind=0.0.0.0 -rpcport=18443 -rpcuser=citrea -rpcpassword=citrea 
```

You can edit RPC parameters as you wish, but you also have to edit `rollup_config.toml`

### Option 2: Run Docker container

If you are also going to run Citrea in Docker, follow [these steps](#tl-dr-i-want-to-run-it-asap).

#### Step 2.1: Install Docker

Follow instructions to install Docker here: https://docs.docker.com/engine/install/

#### Step 2.2: Run testnet4 node:

After Docker is installed, run this command to pull Bitcoin v0.28.0 image and run it as a container:

```sh
docker run -d \
  -v ${PWD}/bitcoin-testnet4:/home/bitcoin/.bitcoin \
  --name bitcoin-testnet4 \
  -p 18443:18443 \
  -p 18444:18444 \
  bitcoin/bitcoin:28.0 \
  -printtoconsole \
  -testnet4=1 \
  -rest \
  -rpcbind=0.0.0.0 \
  -rpcallowip=0.0.0.0/0 \
  -rpcport=18443 \
  -rpcuser=citrea \
  -rpcpassword=citrea \
  -server \
  -txindex=1
```

You can edit RPC parameters as you wish, but you have to also edit `rollup_config.toml`


## Citrea Full Node Setup

There is three different ways to run a Citra full node: using a [pre-built binary](#option-1-using-pre-built-binary), [building from source](#option-2-build-from-source) and [using docker](#option-3-using-docker).

### Option 1: Using pre-built binary

Before continueuing we suggest creating a `citrea/` directory and executing these commands in that directory.

#### Step 1.1: Download necessary files

Go to this [webpage](https://github.com/chainwayxyz/citrea/releases) and download latest binary for your operating system under "Assets" section.

Run this command to download full node config and testnet genesis files:
```sh
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/resources/configs/testnet/rollup_config.toml --output rollup_config.toml
curl https://static.testnet.citrea.xyz/genesis.tar.gz --output genesis.tar.gz
tar -xzvf genesis.tar.gz
```

Look through the `rollup_config.toml` and apply changes as you wish, if you modified any Bitcoin RPC configs, change corresponding values under `[da]`.

#### Step 1.2: Run Citrea Full Node

Finally run this command to run your Citrea full node:

Mac:
```sh
RISC0_DEV_MODE=1 ./citrea-v0.7.2-osx-arm64 --network testnet --da-layer bitcoin --rollup-config-path ./rollup_config.toml --genesis-paths ./genesis
```

or if you wish to use environment variables for configuring your node:

```sh
SEQUENCER_PUBLIC_KEY=0201edff3b3ee593dbef54e2fbdd421070db55e2de2aebe75f398bd85ac97ed364 \
SEQUENCER_DA_PUB_KEY=03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b \
PROVER_DA_PUB_KEY=0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42 \
NODE_URL=http://0.0.0.0:18443 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
NETWORK=testnet \
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
SEQUENCER_CLIENT_URL=https://rpc.testnet.citrea.xyz \
INCLUDE_TX_BODY=false \
SYNC_BLOCKS_COUNT=10 \
RUST_LOG=info \
JSON_LOGS=1 \
RISC0_DEV_MODE=1  \
./citrea-v0.7.2-osx-arm64 --network testnet --da-layer bitcoin --genesis-paths ./genesis
```

Linux:
```sh
RISC0_DEV_MODE=1 ./citrea-v0.7.2-linux-amd64 --network testnet --da-layer bitcoin --rollup-config-path ./rollup_config.toml --genesis-paths ./genesis
```

or if you wish to use environment variables for configuring your node:


```sh
SEQUENCER_PUBLIC_KEY=0201edff3b3ee593dbef54e2fbdd421070db55e2de2aebe75f398bd85ac97ed364 \
SEQUENCER_DA_PUB_KEY=03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b \
PROVER_DA_PUB_KEY=0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42 \
NODE_URL=http://0.0.0.0:18443 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
NETWORK=testnet \
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
SEQUENCER_CLIENT_URL=https://rpc.testnet.citrea.xyz \
INCLUDE_TX_BODY=false \
SYNC_BLOCKS_COUNT=10 \
RUST_LOG=info \
JSON_LOGS=1 \
RISC0_DEV_MODE=1  \
./citrea-v0.7.2-linux-amd64 --network testnet --da-layer bitcoin --genesis-paths ./genesis
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

Citrea ZK proof circuits are read from `resuources/guests`. Rebuilding the circuits are unnecessary if you only wish to run a testnet node, that's why build is made with `SKIP_GUEST_BUILD=1`.

#### Step 2.4: Run Citrea

Look through the `rollup_config.toml` and apply changes as you wish, if you modified any Bitcoin RPC configs, change corresponding values under `[da]`.

And then run the full node by executing this command

```sh
RISC0_DEV_MODE=1 ./target/release/citrea --network testnet --da-layer bitcoin --rollup-config-path ./resources/configs/testnet/rollup_config.toml --genesis-paths ./resources/genesis/testnet
```

If you'd like to use environment variables to pass configs instead of using .toml files you can do so like this:

```sh
SEQUENCER_PUBLIC_KEY=0201edff3b3ee593dbef54e2fbdd421070db55e2de2aebe75f398bd85ac97ed364 \
SEQUENCER_DA_PUB_KEY=03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b \
PROVER_DA_PUB_KEY=0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42 \
NODE_URL=http://0.0.0.0:18443 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
NETWORK=testnet \
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
SEQUENCER_CLIENT_URL=https://rpc.testnet.citrea.xyz \
INCLUDE_TX_BODY=false \
SYNC_BLOCKS_COUNT=10 \
RUST_LOG=info \
JSON_LOGS=1 \
RISC0_DEV_MODE=1  \
./target/release/citrea --network testnet --da-layer bitcoin --genesis-paths ./resources/genesis/testnet
```

If you've made any changes to your bitcoin node url, username or password, don't forget to change values for `NODE_URL`, `NODE_USERNAME` and `NODE_PASSWORD`.

### Option 3: Using Docker

See the [top section](#tl-dr-i-want-to-run-it-asap).
