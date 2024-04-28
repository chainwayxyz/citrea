# Description
This is an offchain db where we store sequencer commmitments details.

## Why is this required for sequencer
Imagine a case where sequencer sends commitment to da layer but crashes while the commitment tx is still in the DA Layers mempool(transaction pool).
In such a case a full node would never know that this commitment exists, so when we spin up a new sequencer from a full node sequencer commitments might get lost.

With the data we can check the last saved commitment in ledger db and offchain db and compare them. If the data is different we move on with th data on offchain DB.