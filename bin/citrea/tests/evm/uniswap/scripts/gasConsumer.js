const { Contract, ContractFactory, utils, constants, BigNumber } = require("ethers");

const assert = require("assert");
const fs = require("fs");
const { promisify } = require("util");


async function main() {
    const [signer] = await ethers.getSigners();
    // assert that owner.address and trader.address are not undefined
    if (!signer || !signer.address) {
        throw new Error("Could not get owner and trader addresses");
    }

    console.log(
        `Starting with owner=${signer.address}`,
    );
    let nonce = await ethers.provider.getTransactionCount(signer.address);
    console.log("using nonce", nonce);
    console.log("deploying gas consumer...");
    const GasConsumer = await ethers.getContractFactory("GasConsumer", signer);
    const gasConsumer = await GasConsumer.deploy({ nonce });
    nonce++;
    // wait for gasConsumer to be deployed
    await gasConsumer.deployTransaction.wait();

    // get storageConsume gas estimate
    const storageGasEstimate = await gasConsumer.connect(signer).estimateGas.storageConsume();
    // get keccakConsume gas estimate
    const keccakGasEstimate = await gasConsumer.connect(signer).estimateGas.keccakConsume();

    console.log("storageGasEstimate", storageGasEstimate.toString());
    console.log("keccakGasEstimate", keccakGasEstimate.toString());

    // devide block to these two txs
    const gasLimit = BigNumber.from(30000000);

    const storageGasTxNum = gasLimit.div(2).div(storageGasEstimate).toNumber();
    const keccakGasTxNum = gasLimit.div(2).div(keccakGasEstimate).toNumber();

    console.log("storageGasTxNum", storageGasTxNum);
    console.log("keccakGasTxNum", keccakGasTxNum);

    console.log("GasConsumer deployed at:", gasConsumer.address);
    let tx;
    for (let i = 0; i < 20; i++) {
        for (let j = 0; j < storageGasTxNum; j++) {
            await gasConsumer.storageConsume({ nonce });
            nonce++;
        }

        for (let j = 0; j < keccakGasTxNum; j++) {
            tx = await gasConsumer.keccakConsume({ nonce });
            nonce++;
        }

        console.log("Round", i + 1, "done");
    }

    // wait until block number is 20
    await tx.wait();

    // sum last 20 blocks gas used
    let totalGasUsed = 0;
    for (let i = 0; i < 21; i++) {
        const block = await ethers.provider.getBlock("latest");
        totalGasUsed += block.gasUsed;
    }

    console.log("Total gas used in last 20 blocks:", totalGasUsed);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
