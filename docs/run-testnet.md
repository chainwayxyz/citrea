#TODO: add volumes for docker commands and docker compose commands


## TL; DR: I want to run it ASAP
Download our testnet docker-compose file:

```sh
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/docker-compose.yml
```

Then use `docker-compose` to both launch a Bitcoin testnet4 node and Citrea full node:
```sh
docker-compose -f docker-compose.ym up
```

# Run a Citrea Testnet Full Node

This guide goes over how to run a full node for Citrea testnet.

It demonstrates different methods for running required software.


## Bitcoin Testnet Setup

Citrea testnet uses Bitcoin testnet4 as its DA and settlement layer.

So running a Citrea fullnode requires a fully synced Bitcoin testnet4 node.

Testnet4 is only enabled in version 28.0rc.1.

### Option 1: Build from source

#### Step 1.1: Clone Bitcoin Core Repo


```sh
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin
git checkout v28.0rc1
```

#### Step 1.2: Build Bitcoin Core

Then follow the instructions on the links below for the build. However, don't clone the repository since we already did.

OSX: https://github.com/bitcoin/bitcoin/blob/v28.0rc1/doc/build-osx.md

Linux: https://github.com/bitcoin/bitcoin/blob/v28.0rc1/doc/build-unix.md


#### Step 1.3: Run testnet4 node:

After the setup, execute these commands to run a Bitcoin testnet4 node:

```sh
bitcoind -testnet4 -daemon -txindex=1 -rpcbind=0.0.0.0 -rpcport=18443 -rpcuser=citrea -rpcpassword=citrea 
```

You can edit RPC parameters as you wish, but you also have to edit `rollup_config.toml`

### Option 2: Run Docker container

#### Step 2.1: Install Docker

Follow instructions to install Docker here: https://docs.docker.com/engine/install/

#### Step 2.2: Run testnet4 node:

After Docker is installed, run this command to pull Bitcoin v0.28rc.1 image and run it as a container:

```sh
docker run -d \
  --name bitcoin-testnet4 \
  -p 18443:18443 \
  -p 18444:18444 \
  bitcoin/bitcoin:28.0rc1 \
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

There is three different ways to run a Citra full node: using a pre-built binary, building from source and using docker.

Our suggestion is if you're going to use docker in this step, also use docker in Bitcoin Testnet4 setup.

### Option 1: Using pre-built binary

Before continueuing we suggest creating a `citrea/` directory and executing these commands in that directory.

#### Step 1.1: Download neccessary files

Go to this [webpage](https://github.com/chainwayxyz/citrea/releases) and download latest binary for your operating system under "Assets" section.

Run this command to download full node config and testnet genesis files:
```sh
curl https://raw.githubusercontent.com/chainwayxyz/citrea/nightly/resources/configs/testnet/rollup_config.toml
curl #TODO: add genesis url
tar -xzvf genesis.tar.gz
```

Look through the `rollup_config.toml` and apply changes as you wish, if you modified any Bitcoin RPC configs, change corresponding values under `[da]`.

#### Step 1.2: Run Citrea Full Node

Finally run this command to run your Citrea full node:

Mac:
```sh
./citrea-v0.5.0-rc.6-osx-arm64 --da-layer bitcoin --rollup-config-path ./rollup_config.toml --genesis-paths ./genesis
```

Linux:
```sh
./citrea-v0.5.0-rc.6-linux-amd64 --da-layer bitcoin --rollup-config-path ./rollup_config.toml --genesis-paths ./genesis
```

Your full node should be serving RPC at `http://0.0.0.0:8080` now.

### Option 2: Building from source


#### Step 2.1: Install Rust

If you don't have it, install it from [here](https://www.rust-lang.org/tools/install).


#### Step 2.2: Clone the source code

#TODO: we can checkout main also
Let's clone the repository and checkout the latest tag:
```sh
git clone https://github.com/chainwayxyz/citrea
cd citrea
git fetch --tags
git checkout $(git describe --tags `git rev-list --tags --max-count=1`)
```

#### Step 2.3: Build Citrea
If you wish to verify ZK-Proofs, then you'll need to compile our ZK VM binaries inside docker. To do so, follow instructions to install Docker: https://docs.docker.com/engine/install/

Compile Citrea by running command:

```sh
cargo build --release
```

If you wish to verify ZK-Proofs, add `REPR_GUEST_BUILD=1` before `cargo b...`

#### Step 2.4: Run Citrea

Look through the `rollup_config.toml` and apply changes as you wish, if you modified any Bitcoin RPC configs, change corresponding values under `[da]`.

And then run the full node by executing this command

```sh
./target/release/citrea --da-layer bitcoin --rollup-config-path ./resources/configs/testnet/rollup_config.toml --genesis-paths ./resources/genesis/testnet
```

### Option 2: Using Docker

Run this command:

```sh
docker run -d \
  --name full-node \
  --platform linux/amd64 \
  --env ROLLUP__PUBLIC_KEYS__SEQUENCER_PUBLIC_KEY=4682a70af1d3fae53a5a26b682e2e75f7a1de21ad5fc8d61794ca889880d39d1 \
  --env ROLLUP__PUBLIC_KEYS__SEQUENCER_DA_PUB_KEY=03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b \
  --env ROLLUP__PUBLIC_KEYS__PROVER_DA_PUB_KEY=0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42 \
  --env ROLLUP__DA__NETWORK=testnet \
  --env ROLLUP__STORAGE__PATH=/mnt/task/citrea-db \
  --env ROLLUP__RPC__BIND_HOST=0.0.0.0 \
  --env ROLLUP__RPC__MAX_CONNECTIONS=1000 \
  --env ROLLUP__RPC__BIND_PORT=8080 \
  --env JSON_LOGS=1 \
  --env ROLLUP__DA__NODE_URL=http://citrea-bitcoin-testnet4:18443/ \
  --env ROLLUP__DA__NODE_USERNAME=citrea \
  --env ROLLUP__DA__NODE_PASSWORD=citrea \
  --env ROLLUP__RUNNER__SEQUENCER_CLIENT_URL=https://rpc.testnet.citrea.xyz \
  --env ROLLUP__RUNNER__INCLUDE_TX_BODY=true \
  --env ROLLUP__STORAGE__DB_MAX_OPEN_FILES=5000 \
  --env RUST_LOG=info \
  --network citrea-testnet-network \
  -p 8080:8080 \
  chainwayxyz/citrea-full-node:testnet
```

Modify `ROLLUP__DA_NODE*` parameters if you have modified the RPC parameters while setting up your Bitcoin testnet4 node.