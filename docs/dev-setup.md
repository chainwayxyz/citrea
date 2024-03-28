## Set up Citrea developer environment

### Linux
```sh
# install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# install dependencies
sudo apt-get install build-essential pkg-config make clang lldb lld libssl-dev

# clone the repo
git clone https://github.com/chainwayxyz/citrea.git

cd citrea

# install dev tools
make install-dev-tools
```

### Mac
```sh
# install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# install dependencies
xcode-select --install
brew install openssl

# clone the repo
git clone https://github.com/chainwayxyz/citrea.git

cd citrea

# install dev tools
make install-dev-tools
```

## Install Bitcoin core for testing with Bitcoin regtest

### Linux
```sh
# install dependencies
sudo apt-get install git build-essential autoconf libtool autotools-dev automake pkg-config bsdmainutils python3 libevent-dev libboost-dev libsqlite3-dev cpufrequtils libssl-dev cargo

# clone the Bitcoin repository
git clone https://github.com/bitcoin/bitcoin.git

cd bitcoin

# checkout the latest release
git checkout v26.0

# some configs 
./autogen.sh
./configure

# get number of cores in the system
CORES=`lscpu|grep "CPU(s)"|head -1|awk '{print $2}'`

# build Bitcoin
make -j $CORES

# install binaries
sudo make install

# check if it works
bitcoind --version
```

### Mac
```sh
brew install bitcoin
```