# Pruning

Citrea nodes can prune old blockchain data to manage disk space. When enabled, the node keeps recent blocks and automatically removes older historical data.

## How It Works

Pruning removes old data from three databases:
- **Ledger DB**: L2 block metadata, commitments, and DA slot mappings
- **State DB**: Historical EVM state (Merkle tree nodes and values)
- **Native DB**: EVM blocks, transactions, and receipts

The pruner keeps the most recent `distance` blocks and removes everything older. It runs automatically in the background as new blocks arrive.

### Trigger Behavior

The pruner checks each new block and triggers when:
```
current_block >= last_pruned_block + (2 × distance)
```

When triggered, it prunes blocks up to:
```
last_pruned_block + distance
```

**Example with distance=259200:**
- At block 518400: Prunes blocks 1-259200
- At block 777600: Prunes blocks 259201-518400
- Keeps the last 259200 blocks available at all times

The 2× multiplier prevents pruning too aggressively - it ensures you always have at least `distance` blocks of history before the next prune cycle.

## Configuration

### In Config File

Add this section to your `rollup_config.toml`:

```toml
[runner.pruning_config]
distance = 259200  # 3 days worth of blocks
```

### Via Environment Variable

```bash
PRUNING_DISTANCE=259200
```

### Default Value

If you don't configure pruning, it's **disabled by default**. The default distance when enabled is 256 blocks.

## What Gets Pruned

Once a block is pruned, you cannot query its state anymore. This means:

- ❌ `eth_getBalance(address, block_number)` for old blocks will fail
- ❌ `eth_call` with historical block numbers won't work
- ❌ Historical transaction receipts become unavailable
- ✅ Recent blocks (within `distance` from chain tip) work normally

## Storage Impact

Without pruning, a full node's database grows continuously - typically 50MB+ per day depending on transaction load.

With pruning enabled (distance=259200):
- Keeps ~3 days of history
- Significantly reduces disk usage
- Database size stabilizes after initial sync

## Running Modes

### Archive Node (No Pruning)
Stores all historical data. Required if you need to serve historical queries or run block explorers.

```toml
# Don't add pruning_config section
```

### Pruned Node
Stores only recent history. Good for validators or personal nodes that don't need full history.

```toml
[runner.pruning_config]
distance = 259200  # 3 days of blocks
```

## Manual Pruning

You can manually prune an existing database using the CLI:

```bash
# Stop your node first

./citrea prune \
  --node-type fullnode \
  --db-path resources/dbs \
  --distance 259200
```

This is useful for:
- One-time cleanup of old data
- Testing pruning behavior
- Migrating from archive to pruned mode

## Examples

### Testnet Full Node with Pruning

**Config file** (`rollup_config.toml`):
```toml
[runner.pruning_config]
distance = 259200  # 3 days of blocks
```

Run:
```bash
./citrea --network testnet --da-layer bitcoin \
  --rollup-config-path ./rollup_config.toml \
  --genesis-paths ./genesis
```

### Using Environment Variables

```bash
PRUNING_DISTANCE=259200 \
NODE_URL=http://0.0.0.0:18443 \
NODE_USERNAME=citrea \
NODE_PASSWORD=citrea \
STORAGE_PATH=resources/dbs \
./citrea --network testnet --da-layer bitcoin --genesis-paths ./genesis
```

