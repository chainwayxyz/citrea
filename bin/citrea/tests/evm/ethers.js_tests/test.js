import { ethers, JsonRpcProvider } from "ethers";
import { expect } from 'chai';

let provider = new JsonRpcProvider('http://127.0.0.1:12345');

describe("RpcTests", function() {
    let first_tx_receipt;
    // Makes an initial tx to test for later, used to prevent waiting for a block to mine
    // in each such test
    before(async function() {
        this.timeout(0);
        let tx = await generateTransaction();
        let signer = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        tx = await signer.signTransaction(tx);
        let tx_response = await provider.broadcastTransaction(tx);
        first_tx_receipt = await tx_response.wait(1);
    });

    it("getBlockNumber should return a positive integer", async function() {
        let number = await provider.getBlockNumber();
        expect(number).to.be.a("number").and.satisfy(Number.isInteger);
        expect(number).to.be.greaterThan(0);
    });

    // Considering we can't test `deposit` actions, the Bridge cannot lose funds but can gain through a `withdraw`
    it("getBalance should return 21 million ether or more for Bridge", async function() {
        let balance = await provider.getBalance("0x3100000000000000000000000000000000000002");
        expect(balance > ethers.parseEther('21000000')).to.be.true;
    });

    it("getNetwork chainId should return 5655", async function() {
        let number = await provider.getNetwork();
        expect(number.chainId).to.equal(5655n);
    });

    it("getFeeData should return positive integers", async function() {
        let feeData = await provider.getFeeData();
        expect(typeof feeData.gasPrice).to.equal('bigint');
        expect(feeData.gasPrice > 0n).to.be.true;
        expect(typeof feeData.maxFeePerGas).to.equal('bigint');
        expect(feeData.maxFeePerGas > 0n).to.be.true;
        expect(typeof feeData.maxPriorityFeePerGas).to.equal('bigint');
        expect(feeData.maxPriorityFeePerGas > 0n).to.be.true;
    });

    it("estimateGas should return a proper value" , async function() {
        const abi = [
            {
                "type": "function",
                "name": "withdraw",
                "inputs": [
                  {
                    "name": "bitcoin_address",
                    "type": "bytes32",
                    "internalType": "bytes32"
                  }
                ],
                "outputs": [],
                "stateMutability": "payable"
              },
        ];

        const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
        const wallet = new ethers.Wallet(privateKey, provider);
        const contractAddress = '0x3100000000000000000000000000000000000002';
        const contract = new ethers.Contract(contractAddress, abi, wallet);
        const bitcoinAddress = ethers.encodeBytes32String('bc1qa0a0a0a0a0a0a0a0a0a0a0a0');

        let gasEstimate = await contract.withdraw.estimateGas(bitcoinAddress, {value: ethers.parseEther('1')});
        expect(gasEstimate > 0n).to.be.true;
    });

    it("call should work properly", async function() {
        let tx = await generateTransaction();
        provider.call(tx);
    });

    it("broadcastTransaction should work properly", async function() {
        this.timeout(0);
        let tx = await generateTransaction();
        let signer = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        tx = await signer.signTransaction(tx);
        let tx_response = await provider.broadcastTransaction(tx);
        await tx_response.wait(1);
    });

    it("getBlock should work properly", async function() {
        let block = await provider.getBlock(first_tx_receipt.blockNumber);
        expect(block.hash).to.equal(first_tx_receipt.blockHash);
    });

    it("getCode returns the correct code", async function() {
        let code = await provider.getCode("0x3100000000000000000000000000000000000001"); // BitcoinLightClient
        expect(code).to.equal("0x608060405234801561001057600080fd5b50600436106100a95760003560e01c806357e871e71161007157806357e871e71461014c57806361b207e214610155578063a91d8b3d14610182578063d269a03e146101a2578063d761753e146101b5578063ee82ac5e146101e857600080fd5b80630466efc4146100ae5780630e27bc11146100e15780631f578333146100f657806334cdf78d146101095780634ffd344a14610129575b600080fd5b6100ce6100bc366004610599565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b6100f46100ef3660046105b2565b610208565b005b6100f4610104366004610599565b610331565b6100ce610117366004610599565b60016020526000908152604090205481565b61013c61013736600461061d565b6103df565b60405190151581526020016100d8565b6100ce60005481565b6100ce610163366004610599565b6000908152600160209081526040808320548352600290915290205490565b6100ce610190366004610599565b60026020526000908152604090205481565b61013c6101b036600461061d565b610405565b6101d073deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b6040516001600160a01b0390911681526020016100d8565b6100ce6101f6366004610599565b60009081526001602052604090205490565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146102705760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b60008054908190036102b65760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b6044820152606401610267565b60008181526001602081905260409091208490556102d5908290610678565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146103945760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610267565b600054156103da5760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b6044820152606401610267565b600055565b6000858152600160205260408120546103fb9086868686610410565b9695505050505050565b60006103fb86868686865b6000858152600260209081526040808320548151601f870184900484028101840190925285825291610463918891849190899089908190840183828082843760009201919091525089925061046e915050565b979650505050505050565b6000838514801561047d575081155b801561048857508251155b15610495575060016104a4565b6104a1858486856104ac565b90505b949350505050565b6000602084516104bc9190610699565b156104c9575060006104a4565b83516000036104da575060006104a4565b818560005b8651811015610549576104f3600284610699565b6001036105175761051061050a8883016020015190565b83610556565b9150610530565b61052d826105288984016020015190565b610556565b91505b60019290921c91610542602082610678565b90506104df565b5090931495945050505050565b6000610562838361056b565b90505b92915050565b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b6000602082840312156105ab57600080fd5b5035919050565b600080604083850312156105c557600080fd5b50508035926020909101359150565b60008083601f8401126105e657600080fd5b50813567ffffffffffffffff8111156105fe57600080fd5b60208301915083602082850101111561061657600080fd5b9250929050565b60008060008060006080868803121561063557600080fd5b8535945060208601359350604086013567ffffffffffffffff81111561065a57600080fd5b610666888289016105d4565b96999598509660600135949350505050565b8082018082111561056557634e487b7160e01b600052601160045260246000fd5b6000826106b657634e487b7160e01b600052601260045260246000fd5b50069056fea26469706673582212202fa9b28760396981b6b0d8418d5de50f0783041c49eced580ada3a97fdbcae6f64736f6c63430008190033");
    });

    it("getStorage returns the correct storage", async function() {
        // 3rd slot of Bridge is 'operator' and should be the system caller address on its own
        let storage = await provider.getStorage("0x3100000000000000000000000000000000000002", 2);
        expect(storage).to.equal("0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead");
    });

    it("getLogs returns the correct logs", async function() {
        const filter = [ethers.id('OperatorUpdated(address,address)')];
        let logs = await provider.getLogs({
            fromBlock: 0,
            toBlock: 'latest',
            address: "0x3100000000000000000000000000000000000002", 
            topics: filter
        }
        );
        expect(logs[0].data).to.be.equal('0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead');
    });



const generateTransaction = async () => {
    const abi = [
        {
            "type": "function",
            "name": "withdraw",
            "inputs": [
                {
                    "name": "bitcoin_address",
                    "type": "bytes32",
                    "internalType": "bytes32"
                }
            ],
            "outputs": [],
            "stateMutability": "payable"
        },
    ];

    const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
    const wallet = new ethers.Wallet(privateKey, provider);
    const contractAddress = '0x3100000000000000000000000000000000000002';
    const contract = new ethers.Contract(contractAddress, abi, wallet);
    const bitcoinAddress = ethers.encodeBytes32String('bc1qa0a0a0a0a0a0a0a0a0a0a0a0');

    let tx = {
        to: contractAddress,
        value: ethers.parseEther('1'),
        data: contract.interface.encodeFunctionData('withdraw', [bitcoinAddress]),
        from: wallet.address,
        chainId: 5655,
        gasLimit: 1000000,
        gasPrice: 1000000,
        nonce: await provider.getTransactionCount(wallet.address),
    };

    return tx;
    };
});