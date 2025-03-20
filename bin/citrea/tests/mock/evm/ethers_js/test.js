import { ethers, JsonRpcProvider } from "ethers";
import { expect } from 'chai';

let provider = new JsonRpcProvider('http://127.0.0.1:12346');

describe("RpcTests", function() {
    let first_tx_receipt;
    //Makes an initial tx to test for later, used to prevent waiting for a block to mine in each such test
    before(async function() {
        this.timeout(0);
        let tx = await generateTransaction('10');
        let signer = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        tx = await signer.signTransaction(tx);
        let tx_response = await provider.broadcastTransaction(tx);
        first_tx_receipt = await tx_response.wait(1);
    });

    it("getBlockNumber returns a positive integer", async function() {
        let number = await provider.getBlockNumber();
        expect(number).to.be.a("number").and.satisfy(Number.isInteger);
        expect(number).to.be.greaterThan(0);
    });

    // Considering we can't test `deposit` actions, the Bridge cannot lose funds but can gain through a `withdraw`
    it("getBalance returns 21 million ether or more for Bridge", async function() {
        let balance = await provider.getBalance("0x3100000000000000000000000000000000000002");
        expect(balance > ethers.parseEther('21000000')).to.be.true;
    });

    it("getNetwork chainId returns 5655", async function() {
        let number = await provider.getNetwork();
        expect(number.chainId).to.equal(5655n);
    });

    it("getFeeData returns positive integers", async function() {
        let feeData = await provider.getFeeData();
        expect(typeof feeData.gasPrice).to.equal('bigint');
        expect(feeData.gasPrice > 0n).to.be.true;
        expect(typeof feeData.maxFeePerGas).to.equal('bigint');
        expect(feeData.maxFeePerGas > 0n).to.be.true; // base should be > 0 always
        expect(typeof feeData.maxPriorityFeePerGas).to.equal('bigint');
        expect(feeData.maxPriorityFeePerGas >= 0n).to.be.true; // for priority it can be 0
    });

    it("estimateGas returns a positive integer" , async function() {
        const abi = [
            {
                "type": "function",
                "name": "withdraw",
                "inputs": [
                  {
                    "name": "txId",
                    "type": "bytes32",
                    "internalType": "bytes32"
                  },
                  {
                    "name": "outputId",
                    "type": "bytes4",
                    "internalType": "bytes4"
                  }
                ],
                "outputs": [],
                "stateMutability": "payable"
              }
        ];

        const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
        const wallet = new ethers.Wallet(privateKey, provider);
        const contractAddress = '0x3100000000000000000000000000000000000002';
        const contract = new ethers.Contract(contractAddress, abi, wallet);
        const txId = ethers.encodeBytes32String('0x1234');
        const outputId = ethers.zeroPadBytes(ethers.toUtf8Bytes('0x01'), 4);

        let gasEstimate = await contract.withdraw.estimateGas(txId, outputId, {value: ethers.parseEther('10')});
        expect(gasEstimate > 0n).to.be.true;
    });

    it("call returns a correct value on a view function", async function() {
        const abi = [
            {
                "type": "function",
                "name": "SYSTEM_CALLER",
                "inputs": [],
                "outputs": [
                  {
                    "name": "",
                    "type": "address",
                    "internalType": "address"
                  }
                ],
                "stateMutability": "view"
              },
        ];

        const contractAddress = '0x3100000000000000000000000000000000000001';
        const contract = new ethers.Contract(contractAddress, abi, provider);

        let tx = {
            to: "0x3100000000000000000000000000000000000001",
            data: contract.interface.encodeFunctionData('SYSTEM_CALLER', []),
            chainId: 5655,
        };

        let result = await provider.call(tx);
        expect(result).to.equal("0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead");
    });

    it("broadcastTransaction publishes a txn and it gets mined", async function() {
        this.timeout(0);
        let tx = await generateTransaction('10');
        let signer = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        tx = await signer.signTransaction(tx);
        let tx_response = await provider.broadcastTransaction(tx);
        await tx_response.wait(1);
    });

    it("getBlock returns correct block info", async function() {
        let block = await provider.getBlock(first_tx_receipt.blockNumber);
        expect(block.hash).to.equal(first_tx_receipt.blockHash);
    });

    it("getCode returns the correct code", async function() {
        let code = await provider.getCode("0x3200000000000000000000000000000000000001"); // BitcoinLightClient
        expect(code).to.equal("0x608060405234801561000f575f5ffd5b50600436106100cb575f3560e01c8063a91d8b3d11610088578063d269a03e11610063578063d269a03e146101dd578063d5ba11fa146101f0578063d761753e14610203578063ee82ac5e14610236575f5ffd5b8063a91d8b3d1461018c578063abb068d6146101ab578063cd4cc08f146101ca575f5ffd5b80630466efc4146100cf5780631f5783331461010157806334cdf78d146101165780634ffd344a1461013557806357e871e71461015857806361b207e214610160575b5f5ffd5b6100ee6100dd3660046107f6565b5f9081526002602052604090205490565b6040519081526020015b60405180910390f35b61011461010f3660046107f6565b610255565b005b6100ee6101243660046107f6565b60016020525f908152604090205481565b610148610143366004610852565b610306565b60405190151581526020016100f8565b6100ee5f5481565b6100ee61016e3660046107f6565b5f908152600160209081526040808320548352600290915290205490565b6100ee61019a3660046107f6565b60026020525f908152604090205481565b6100ee6101b93660046107f6565b60036020525f908152604090205481565b6101486101d83660046108a8565b61032b565b6101486101eb366004610852565b6104b1565b6101146101fe366004610932565b6104bf565b61021e73deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b6040516001600160a01b0390911681526020016100f8565b6100ee6102443660046107f6565b5f9081526001602052604090205490565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146102bd5760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b5f54156103025760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b60448201526064016102b4565b5f55565b5f8581526001602052604081205461032190868686866105f1565b9695505050505050565b5f5f61036b87878080601f0160208091040260200160405190810160405280939291908181526020018383808284375f920191909152506106ab92505050565b5f8a81526001602052604090205490915081146103c15760405162461bcd60e51b815260206004820152601460248201527324b73b30b634b210313637b1b5903432b0b232b960611b60448201526064016102b4565b5f818152600360209081526040909120546103db9161096f565b84146104205760405162461bcd60e51b8152602060048201526014602482015273092dcecc2d8d2c840e0e4dedecc40d8cadccee8d60631b60448201526064016102b4565b5f61045f88888080601f0160208091040260200160405190810160405280939291908181526020018383808284375f920191909152506106cd92505050565b90506104a3898288888080601f0160208091040260200160405190810160405280939291908181526020018383808284375f920191909152508a92506106db915050565b9a9950505050505050505050565b5f61032186868686866105f1565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146105225760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064016102b4565b5f8054908190036105675760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b60448201526064016102b4565b5f818152600160208190526040909120859055610585908290610986565b5f90815584815260026020908152604080832086905560038252918290208490558151838152908101869052908101849052606081018390527f4975e407627f5c539dcd7c961396db91c315f4421c3b0023ba1bcf2e9e9b41f19060800160405180910390a150505050565b5f85815260036020908152604082205461060a9161096f565b831461064f5760405162461bcd60e51b8152602060048201526014602482015273092dcecc2d8d2c840e0e4dedecc40d8cadccee8d60631b60448201526064016102b4565b5f86815260026020908152604091829020548251601f8701839004830281018301909352858352916106a0918891849189908990819084018382808284375f920191909152508992506106db915050565b979650505050505050565b5f60205f83516020850160025afa5060205f60205f60025afa50505f51919050565b60448101515f905b92915050565b5f83851480156106e9575081155b80156106f457508251155b1561070157506001610710565b61070d85848685610718565b90505b949350505050565b5f602084516107279190610999565b1561073357505f610710565b83515f0361074257505f610710565b81855f5b86518110156107b05761075a600284610999565b60010361077e576107776107718883016020015190565b836107bd565b9150610797565b6107948261078f8984016020015190565b6107bd565b91505b60019290921c916107a9602082610986565b9050610746565b5090931495945050505050565b5f6107c883836107cf565b9392505050565b5f825f528160205260205f60405f60025afa5060205f60205f60025afa50505f5192915050565b5f60208284031215610806575f5ffd5b5035919050565b5f5f83601f84011261081d575f5ffd5b50813567ffffffffffffffff811115610834575f5ffd5b60208301915083602082850101111561084b575f5ffd5b9250929050565b5f5f5f5f5f60808688031215610866575f5ffd5b8535945060208601359350604086013567ffffffffffffffff81111561088a575f5ffd5b6108968882890161080d565b96999598509660600135949350505050565b5f5f5f5f5f5f5f60a0888a0312156108be575f5ffd5b8735965060208801359550604088013567ffffffffffffffff8111156108e2575f5ffd5b6108ee8a828b0161080d565b909650945050606088013567ffffffffffffffff81111561090d575f5ffd5b6109198a828b0161080d565b989b979a50959894979596608090950135949350505050565b5f5f5f60608486031215610944575f5ffd5b505081359360208301359350604090920135919050565b634e487b7160e01b5f52601160045260245ffd5b80820281158282048414176106d5576106d561095b565b808201808211156106d5576106d561095b565b5f826109b357634e487b7160e01b5f52601260045260245ffd5b50069056");
    });

    it("getStorage returns the correct storage", async function() {
        // 2rd slot of Bridge is 'operator' and should be the system caller address on its own
        let storage = await provider.getStorage("0x3100000000000000000000000000000000000002", 0);
        expect(storage).to.equal("0x0000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead01");
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

    it("getTransaction returns the correct transaction", async function() {
        let tx = await provider.getTransaction(first_tx_receipt.hash);
        expect(tx.hash).to.equal(first_tx_receipt.hash);
        expect(tx.blockNumber).to.equal(first_tx_receipt.blockNumber);
        expect(tx.index).to.equal(first_tx_receipt.index);
    });

    it("getTransactionCount returns a positive integer on an active address", async function() {
        let count = await provider.getTransactionCount("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        expect(count > 0).to.be.true;
    });

    it("getTransactionReceipt returns the correct receipt", async function() {
        let receipt = await provider.getTransactionReceipt(first_tx_receipt.hash);
        expect(receipt.hash).to.equal(first_tx_receipt.hash);
        expect(receipt.blockNumber).to.equal(first_tx_receipt.blockNumber);
        expect(receipt.index).to.equal(first_tx_receipt.index);
    });

    it("call on non-existent function errors with the correct message", async function() {
        const abi = [
            {
                "type": "function",
                "name": "ERRENOUS_FUNC",
                "inputs": [],
                "outputs": [
                  {
                    "name": "",
                    "type": "address",
                    "internalType": "address"
                  }
                ],
                "stateMutability": "view"
              },
        ];

        const contractAddress = '0x3100000000000000000000000000000000000001';
        const contract = new ethers.Contract(contractAddress, abi, provider);

        let tx = {
            to: "0x3100000000000000000000000000000000000001",
            data: contract.interface.encodeFunctionData('ERRENOUS_FUNC', []),
            chainId: 5655,
        };

        try {
            await provider.call(tx);
            expect.fail('Expected an error to be thrown');
        } catch (error) {
            expect(error.message).to.equal('missing revert data (action="call", data=null, reason=null, transaction={ "data": "0xd6c7a27a", "to": "0x3100000000000000000000000000000000000001" }, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.13.4)');
        }        
    });

    it("call with wrong function parameters errors with the correct message", async function() {
        this.timeout(0);
        
        const abi = [
            {
                "type": "function",
                "name": "withdraw",
                "inputs": [
                  {
                    "name": "txId",
                    "type": "bytes32",
                    "internalType": "bytes32"
                  },
                  {
                    "name": "outputId",
                    "type": "bytes4",
                    "internalType": "bytes4"
                  }
                ],
                "outputs": [],
                "stateMutability": "payable"
              }
        ];
    
        const contractAddress = '0x3100000000000000000000000000000000000002';
        let wallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        const contract = new ethers.Contract(contractAddress, abi, wallet);
        const txId = ethers.encodeBytes32String('0x1234');
        const outputId = ethers.zeroPadBytes(ethers.toUtf8Bytes('0x01'), 4);
    
        let tx = {
            to: contractAddress,
            value: ethers.parseEther('9'),
            data: contract.interface.encodeFunctionData('withdraw', [txId, outputId]),
            from: wallet.address
        };

        try {
            await provider.call(tx);
            expect.fail('Expected an error to be thrown');
        } catch (error) {
            expect(error.message).to.equal('execution reverted: "Invalid withdraw amount" (action="call", data="0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000017496e76616c696420776974686472617720616d6f756e74000000000000000000", reason="Invalid withdraw amount", transaction={ "data": "0x8786dba730783132333400000000000000000000000000000000000000000000000000003078303100000000000000000000000000000000000000000000000000000000", "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "to": "0x3100000000000000000000000000000000000002" }, invocation=null, revert={ "args": [ "Invalid withdraw amount" ], "name": "Error", "signature": "Error(string)" }, code=CALL_EXCEPTION, version=6.13.4)');
        }
    });

    it("broadcastTransaction with wrong function parameters errors with the correct message", async function() {
        this.timeout(0);
        let tx = await generateTransaction('0.9');
        let signer = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        tx = await signer.signTransaction(tx);
        try {
            let tx_response = await provider.broadcastTransaction(tx);
            tx_receipt = await tx_response.wait(2);
            expect.fail('Expected an error to be thrown');
        } catch (error) {
            expect(error.message).to.match(/transaction execution reverted \(action="sendTransaction", data=null, reason=null, invocation=null, revert=null, transaction={ "data": "", "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "to": "0x3100000000000000000000000000000000000002" }, receipt={ "_type": "TransactionReceipt", "blobGasPrice": null, "blobGasUsed": null, "blockHash": "0x[0-9a-fA-F]+", "blockNumber": \d+, "contractAddress": null, "cumulativeGasUsed": "\d+", "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "gasPrice": "10000000", "gasUsed": "\d+", "hash": "0x[0-9a-fA-F]+", "index": \d, "logs": \[  ], "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "root": null, "status": 0, "to": "0x3100000000000000000000000000000000000002" }, code=CALL_EXCEPTION, version=6\.13\.4\)/);
        }
    });

    it("getTransaction with wrong hash returns null", async function() {
        let tx = await provider.getTransaction('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
        expect(tx).to.be.null;
    });

    it("getTransactionReceipt with wrong hash returns null", async function() {
        let tx = await provider.getTransactionReceipt('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
        expect(tx).to.be.null;
    });

    it("getBlock with wrong hash returns null", async function() {
        let block = await provider.getBlock('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
        expect(block).to.be.null;
    });

    it("getLogs with wrong filter returns empty array", async function() {
        const filter = [ethers.id('I_DO_NOT_EXIST(address)')];
        let logs = await provider.getLogs({
            fromBlock: 0,
            toBlock: 'latest',
            address: "0x3100000000000000000000000000000000000002", 
            topics: filter
        }
        );
        expect(logs).to.be.empty;
    });

    it("getBalance with different block numbers returns the correct balance at the time", async function() {
        let balance = await provider.getBalance("0x3100000000000000000000000000000000000002", 0);
        expect(balance).to.equal(ethers.parseEther('21000000'));
        let balanceNow = await provider.getBalance("0x3100000000000000000000000000000000000002");
        expect(balanceNow > ethers.parseEther('21000000')).to.be.true;
    });

const generateTransaction = async (ether_value) => {
    const abi = [
        {
            "type": "function",
            "name": "withdraw",
            "inputs": [
              {
                "name": "txId",
                "type": "bytes32",
                "internalType": "bytes32"
              },
              {
                "name": "outputId",
                "type": "bytes4",
                "internalType": "bytes4"
              }
            ],
            "outputs": [],
            "stateMutability": "payable"
          }
    ];

    const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
    const wallet = new ethers.Wallet(privateKey, provider);
    const contractAddress = '0x3100000000000000000000000000000000000002';
    const contract = new ethers.Contract(contractAddress, abi, wallet);
    const txId = ethers.encodeBytes32String('0x1234');
    const outputId = ethers.zeroPadBytes(ethers.toUtf8Bytes('0x01'), 4);

    let tx = {
        to: contractAddress,
        value: ethers.parseEther(ether_value),
        data: contract.interface.encodeFunctionData('withdraw', [txId, outputId]),
        from: wallet.address,
        chainId: 5655,
        gasLimit: 1000000,
        gasPrice: 10000000,
        nonce: await provider.getTransactionCount(wallet.address),
    };

    return tx;
    };
});

describe("ContractInteractionTests", function() {
    it("Can deploy a contract (WETH9), interact with that contract and receive an ERC20", async function() {
        this.timeout(0);

        const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
        const wallet = new ethers.Wallet(privateKey, provider);

        // ABI of WETH9
        const abi = [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"withdraw","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}]
        const initcode = "60606040526040805190810160405280600d81526020017f57726170706564204574686572000000000000000000000000000000000000008152506000908051906020019061004f9291906100c8565b506040805190810160405280600481526020017f57455448000000000000000000000000000000000000000000000000000000008152506001908051906020019061009b9291906100c8565b506012600260006101000a81548160ff021916908360ff16021790555034156100c357600080fd5b61016d565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061010957805160ff1916838001178555610137565b82800160010185558215610137579182015b8281111561013657825182559160200191906001019061011b565b5b5090506101449190610148565b5090565b61016a91905b8082111561016657600081600090555060010161014e565b5090565b90565b610c348061017c6000396000f3006060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b9578063095ea7b31461014757806318160ddd146101a157806323b872dd146101ca5780632e1a7d4d14610243578063313ce5671461026657806370a082311461029557806395d89b41146102e2578063a9059cbb14610370578063d0e30db0146103ca578063dd62ed3e146103d4575b6100b7610440565b005b34156100c457600080fd5b6100cc6104dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561010c5780820151818401526020810190506100f1565b50505050905090810190601f1680156101395780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561015257600080fd5b610187600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061057b565b604051808215151515815260200191505060405180910390f35b34156101ac57600080fd5b6101b461066d565b6040518082815260200191505060405180910390f35b34156101d557600080fd5b610229600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061068c565b604051808215151515815260200191505060405180910390f35b341561024e57600080fd5b61026460048080359060200190919050506109d9565b005b341561027157600080fd5b610279610b05565b604051808260ff1660ff16815260200191505060405180910390f35b34156102a057600080fd5b6102cc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b18565b6040518082815260200191505060405180910390f35b34156102ed57600080fd5b6102f5610b30565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561033557808201518184015260208101905061031a565b50505050905090810190601f1680156103625780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561037b57600080fd5b6103b0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610bce565b604051808215151515815260200191505060405180910390f35b6103d2610440565b005b34156103df57600080fd5b61042a600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610be3565b6040518082815260200191505060405180910390f35b34600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055503373ffffffffffffffffffffffffffffffffffffffff167fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c346040518082815260200191505060405180910390a2565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b505050505081565b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156106dc57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16141580156107b457507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414155b156108cf5781600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561084457600080fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a2757600080fd5b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501515610ab457600080fd5b3373ffffffffffffffffffffffffffffffffffffffff167f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65826040518082815260200191505060405180910390a250565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610bc65780601f10610b9b57610100808354040283529160200191610bc6565b820191906000526020600020905b815481529060010190602001808311610ba957829003601f168201915b505050505081565b6000610bdb33848461068c565b905092915050565b60046020528160005260406000206020528060005260406000206000915091505054815600a165627a7a72305820deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a0029";
        const factory = new ethers.ContractFactory(abi, initcode, wallet);
        const WETH = await factory.deploy();
        await WETH.waitForDeployment();

        let code = await provider.getCode(await WETH.getAddress());
        // Deployed bytecode of WETH9
        expect(code).to.equal("0x6060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b9578063095ea7b31461014757806318160ddd146101a157806323b872dd146101ca5780632e1a7d4d14610243578063313ce5671461026657806370a082311461029557806395d89b41146102e2578063a9059cbb14610370578063d0e30db0146103ca578063dd62ed3e146103d4575b6100b7610440565b005b34156100c457600080fd5b6100cc6104dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561010c5780820151818401526020810190506100f1565b50505050905090810190601f1680156101395780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561015257600080fd5b610187600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061057b565b604051808215151515815260200191505060405180910390f35b34156101ac57600080fd5b6101b461066d565b6040518082815260200191505060405180910390f35b34156101d557600080fd5b610229600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061068c565b604051808215151515815260200191505060405180910390f35b341561024e57600080fd5b61026460048080359060200190919050506109d9565b005b341561027157600080fd5b610279610b05565b604051808260ff1660ff16815260200191505060405180910390f35b34156102a057600080fd5b6102cc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b18565b6040518082815260200191505060405180910390f35b34156102ed57600080fd5b6102f5610b30565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561033557808201518184015260208101905061031a565b50505050905090810190601f1680156103625780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561037b57600080fd5b6103b0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610bce565b604051808215151515815260200191505060405180910390f35b6103d2610440565b005b34156103df57600080fd5b61042a600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610be3565b6040518082815260200191505060405180910390f35b34600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055503373ffffffffffffffffffffffffffffffffffffffff167fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c346040518082815260200191505060405180910390a2565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b505050505081565b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156106dc57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16141580156107b457507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414155b156108cf5781600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561084457600080fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a2757600080fd5b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501515610ab457600080fd5b3373ffffffffffffffffffffffffffffffffffffffff167f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65826040518082815260200191505060405180910390a250565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610bc65780601f10610b9b57610100808354040283529160200191610bc6565b820191906000526020600020905b815481529060010190602001808311610ba957829003601f168201915b505050505081565b6000610bdb33848461068c565b905092915050565b60046020528160005260406000206020528060005260406000206000915091505054815600a165627a7a72305820deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a0029");
        
        await (await WETH.deposit({value: ethers.parseEther("1")})).wait();
        
        let balance = await WETH.balanceOf(await wallet.getAddress());
        expect(balance).to.equal(ethers.parseEther("1"));
    });
});