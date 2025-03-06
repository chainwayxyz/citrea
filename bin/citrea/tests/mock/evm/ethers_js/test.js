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
        expect(code).to.equal("0x608060405234801561000f575f5ffd5b50600436106100e8575f3560e01c8063a91d8b3d1161008a578063d269a03e11610064578063d269a03e14610292578063d5ba11fa146102c2578063d761753e146102de578063ee82ac5e146102fc576100e8565b8063a91d8b3d14610202578063abb068d614610232578063cd4cc08f14610262576100e8565b806334cdf78d116100c657806334cdf78d146101545780634ffd344a1461018457806357e871e7146101b457806361b207e2146101d2576100e8565b80630466efc4146100ec5780630e27bc111461011c5780631f57833314610138575b5f5ffd5b61010660048036038101906101019190610bee565b61032c565b6040516101139190610c28565b60405180910390f35b61013660048036038101906101319190610c41565b610346565b005b610152600480360381019061014d9190610cb2565b61048d565b005b61016e60048036038101906101699190610cb2565b61055b565b60405161017b9190610c28565b60405180910390f35b61019e60048036038101906101999190610d3e565b610570565b6040516101ab9190610ddc565b60405180910390f35b6101bc61059a565b6040516101c99190610e04565b60405180910390f35b6101ec60048036038101906101e79190610cb2565b61059f565b6040516101f99190610c28565b60405180910390f35b61021c60048036038101906102179190610bee565b6105ca565b6040516102299190610c28565b60405180910390f35b61024c60048036038101906102479190610bee565b6105df565b6040516102599190610e04565b60405180910390f35b61027c60048036038101906102779190610e1d565b6105f4565b6040516102899190610ddc565b60405180910390f35b6102ac60048036038101906102a79190610ed4565b6107a6565b6040516102b99190610ddc565b60405180910390f35b6102dc60048036038101906102d79190610f58565b6107bf565b005b6102e661091f565b6040516102f39190610fe7565b60405180910390f35b61031660048036038101906103119190610cb2565b610937565b6040516103239190610c28565b60405180910390f35b5f60025f8381526020019081526020015f20549050919050565b73deaddeaddeaddeaddeaddeaddeaddeaddeaddead73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146103c8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103bf9061105a565b60405180910390fd5b5f5f5490505f810361040f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610406906110c2565b60405180910390fd5b8260015f8381526020019081526020015f2081905550600181610432919061110d565b5f819055508160025f8581526020019081526020015f20819055507f87071b99941c479317961cac97dfdb285d86f27155d4d9673a478ad5225459cd81848460405161048093929190611140565b60405180910390a1505050565b73deaddeaddeaddeaddeaddeaddeaddeaddeaddead73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461050f576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105069061105a565b60405180910390fd5b5f5f5414610552576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610549906111bf565b60405180910390fd5b805f8190555050565b6001602052805f5260405f205f915090505481565b5f61058f60015f8881526020019081526020015f205486868686610951565b905095945050505050565b5f5481565b5f60025f60015f8581526020019081526020015f205481526020019081526020015f20549050919050565b6002602052805f5260405f205f915090505481565b6003602052805f5260405f205f915090505481565b5f5f61064287878080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f82011690508083019250505050505050610a24565b90508060015f8b81526020019081526020015f205414610697576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161068e90611227565b60405180910390fd5b602060035f8381526020019081526020015f20546106b59190611245565b85859050146106f9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016106f0906112d0565b60405180910390fd5b5f61074688888080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f82011690508083019250505050505050610a47565b9050610797898288888080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f8201169050808301925050505050505087610a63565b92505050979650505050505050565b5f6107b48686868686610951565b905095945050505050565b73deaddeaddeaddeaddeaddeaddeaddeaddeaddead73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610841576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108389061105a565b60405180910390fd5b5f5f5490505f8103610888576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161087f906110c2565b60405180910390fd5b8360015f8381526020019081526020015f20819055506001816108ab919061110d565b5f819055508260025f8681526020019081526020015f20819055508160035f8681526020019081526020015f20819055507f4975e407627f5c539dcd7c961396db91c315f4421c3b0023ba1bcf2e9e9b41f18185858560405161091194939291906112ee565b60405180910390a150505050565b73deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b5f60015f8381526020019081526020015f20549050919050565b5f602060035f8881526020019081526020015f20546109709190611245565b84849050146109b4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109ab906112d0565b60405180910390fd5b5f60025f8881526020019081526020015f20549050610a18868287878080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f8201169050808301925050505050505086610a63565b91505095945050505050565b5f60205f83516020850160025afa5060205f60205f60025afa505f519050919050565b5f610a5c602483610aa390919063ffffffff16565b9050919050565b5f8385148015610a7257505f82145b8015610a7e57505f8351145b15610a8c5760019050610a9b565b610a9885848685610ab3565b90505b949350505050565b5f81602084010151905092915050565b5f5f60208551610ac3919061135e565b14610ad0575f9050610b70565b5f845103610ae0575f9050610b70565b5f8290505f8690505f5f90505b8651811015610b67576001600284610b05919061135e565b03610b2d57610b26610b208289610aa390919063ffffffff16565b83610b78565b9150610b4c565b610b4982610b44838a610aa390919063ffffffff16565b610b78565b91505b600183901c9250602081610b60919061110d565b9050610aed565b50848114925050505b949350505050565b5f610b838383610b8b565b905092915050565b5f825f528160205260205f60405f60025afa5060205f60205f60025afa505f51905092915050565b5f5ffd5b5f5ffd5b5f819050919050565b610bcd81610bbb565b8114610bd7575f5ffd5b50565b5f81359050610be881610bc4565b92915050565b5f60208284031215610c0357610c02610bb3565b5b5f610c1084828501610bda565b91505092915050565b610c2281610bbb565b82525050565b5f602082019050610c3b5f830184610c19565b92915050565b5f5f60408385031215610c5757610c56610bb3565b5b5f610c6485828601610bda565b9250506020610c7585828601610bda565b9150509250929050565b5f819050919050565b610c9181610c7f565b8114610c9b575f5ffd5b50565b5f81359050610cac81610c88565b92915050565b5f60208284031215610cc757610cc6610bb3565b5b5f610cd484828501610c9e565b91505092915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f840112610cfe57610cfd610cdd565b5b8235905067ffffffffffffffff811115610d1b57610d1a610ce1565b5b602083019150836001820283011115610d3757610d36610ce5565b5b9250929050565b5f5f5f5f5f60808688031215610d5757610d56610bb3565b5b5f610d6488828901610c9e565b9550506020610d7588828901610bda565b945050604086013567ffffffffffffffff811115610d9657610d95610bb7565b5b610da288828901610ce9565b93509350506060610db588828901610c9e565b9150509295509295909350565b5f8115159050919050565b610dd681610dc2565b82525050565b5f602082019050610def5f830184610dcd565b92915050565b610dfe81610c7f565b82525050565b5f602082019050610e175f830184610df5565b92915050565b5f5f5f5f5f5f5f60a0888a031215610e3857610e37610bb3565b5b5f610e458a828b01610c9e565b9750506020610e568a828b01610bda565b965050604088013567ffffffffffffffff811115610e7757610e76610bb7565b5b610e838a828b01610ce9565b9550955050606088013567ffffffffffffffff811115610ea657610ea5610bb7565b5b610eb28a828b01610ce9565b93509350506080610ec58a828b01610c9e565b91505092959891949750929550565b5f5f5f5f5f60808688031215610eed57610eec610bb3565b5b5f610efa88828901610bda565b9550506020610f0b88828901610bda565b945050604086013567ffffffffffffffff811115610f2c57610f2b610bb7565b5b610f3888828901610ce9565b93509350506060610f4b88828901610c9e565b9150509295509295909350565b5f5f5f60608486031215610f6f57610f6e610bb3565b5b5f610f7c86828701610bda565b9350506020610f8d86828701610bda565b9250506040610f9e86828701610c9e565b9150509250925092565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610fd182610fa8565b9050919050565b610fe181610fc7565b82525050565b5f602082019050610ffa5f830184610fd8565b92915050565b5f82825260208201905092915050565b7f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572005f82015250565b5f611044601f83611000565b915061104f82611010565b602082019050919050565b5f6020820190508181035f83015261107181611038565b9050919050565b7f4e6f7420696e697469616c697a656400000000000000000000000000000000005f82015250565b5f6110ac600f83611000565b91506110b782611078565b602082019050919050565b5f6020820190508181035f8301526110d9816110a0565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61111782610c7f565b915061112283610c7f565b925082820190508082111561113a576111396110e0565b5b92915050565b5f6060820190506111535f830186610df5565b6111606020830185610c19565b61116d6040830184610c19565b949350505050565b7f416c726561647920696e697469616c697a6564000000000000000000000000005f82015250565b5f6111a9601383611000565b91506111b482611175565b602082019050919050565b5f6020820190508181035f8301526111d68161119d565b9050919050565b7f496e76616c696420626c6f636b206865616465720000000000000000000000005f82015250565b5f611211601483611000565b915061121c826111dd565b602082019050919050565b5f6020820190508181035f83015261123e81611205565b9050919050565b5f61124f82610c7f565b915061125a83610c7f565b925082820261126881610c7f565b9150828204841483151761127f5761127e6110e0565b5b5092915050565b7f496e76616c69642070726f6f66206c656e6774680000000000000000000000005f82015250565b5f6112ba601483611000565b91506112c582611286565b602082019050919050565b5f6020820190508181035f8301526112e7816112ae565b9050919050565b5f6080820190506113015f830187610df5565b61130e6020830186610c19565b61131b6040830185610c19565b6113286060830184610df5565b95945050505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61136882610c7f565b915061137383610c7f565b92508261138357611382611331565b5b82820690509291505056");
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