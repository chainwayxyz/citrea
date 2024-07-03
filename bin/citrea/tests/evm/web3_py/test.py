import unittest
from hexbytes import HexBytes
from web3 import Web3

class TestWeb3(unittest.TestCase):
    def setUp(self):
        self.web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:12346'))
        transaction = {
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'to': "0x0000000000000000000000000000000000000000",
            'value': 1000000000,
            'nonce': self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            'gas': 200000,
            'gasPrice': self.web3.eth.gas_price,
        }
        signed_tx = self.web3.eth.account.sign_transaction(transaction, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        self.first_tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        self.web3.eth.wait_for_transaction_receipt(self.first_tx_hash)

    def test_connection(self):
        self.assertEqual(self.web3.is_connected(), True)
    
    def test_max_priority_fee(self):
        max_priority_fee = self.web3.eth.max_priority_fee
        self.assertGreater(max_priority_fee, 0)

    def test_gas_price(self):
        gas_price = self.web3.eth.gas_price
        self.assertGreater(gas_price, 0)

    def test_chain_id(self):
        chain_id = self.web3.eth.chain_id
        self.assertEqual(chain_id, 5655)

    def test_block_number(self):
        block_number = self.web3.eth.get_block_number()
        self.assertIsInstance(self.web3.eth.get_block_number(), int)
        self.assertGreater(block_number, 0)

    def test_get_balance(self):
        balance = self.web3.eth.get_balance('0x3100000000000000000000000000000000000002')
        self.assertGreaterEqual(balance, (21 * 10 ** 6) * 10 ** 18)

    def test_get_storage_at(self):
        slot = self.web3.eth.get_storage_at("0x3100000000000000000000000000000000000002", 0)
        self.assertEqual(slot, HexBytes('0x0000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead01'))

    def test_get_code(self):
        code = self.web3.eth.get_code('0x3200000000000000000000000000000000000001')
        self.assertEqual(code, HexBytes('0x6080604052600436106101145760003560e01c8063715018a6116100a0578063d269a03e11610064578063d269a03e14610332578063d761753e14610352578063e30c39781461037a578063ee82ac5e1461038f578063f2fde38b146103bc57600080fd5b8063715018a61461027057806379ba5097146102855780638da5cb5b1461029a578063a91d8b3d146102c7578063ad3cb1cc146102f457600080fd5b80634f1ef286116100e75780634f1ef286146101c85780634ffd344a146101db57806352d1902d1461020b57806357e871e71461022057806361b207e21461023657600080fd5b80630466efc4146101195780630e27bc11146101595780631f5783331461017b57806334cdf78d1461019b575b600080fd5b34801561012557600080fd5b50610146610134366004610d50565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b34801561016557600080fd5b50610179610174366004610d69565b6103dc565b005b34801561018757600080fd5b50610179610196366004610d50565b610505565b3480156101a757600080fd5b506101466101b6366004610d50565b60016020526000908152604090205481565b6101796101d6366004610dbd565b6105b3565b3480156101e757600080fd5b506101fb6101f6366004610ec8565b6105d2565b6040519015158152602001610150565b34801561021757600080fd5b506101466105f8565b34801561022c57600080fd5b5061014660005481565b34801561024257600080fd5b50610146610251366004610d50565b6000908152600160209081526040808320548352600290915290205490565b34801561027c57600080fd5b50610179610615565b34801561029157600080fd5b50610179610629565b3480156102a657600080fd5b506102af610671565b6040516001600160a01b039091168152602001610150565b3480156102d357600080fd5b506101466102e2366004610d50565b60026020526000908152604090205481565b34801561030057600080fd5b50610325604051806040016040528060058152602001640352e302e360dc1b81525081565b6040516101509190610f47565b34801561033e57600080fd5b506101fb61034d366004610ec8565b6106a6565b34801561035e57600080fd5b506102af73deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b34801561038657600080fd5b506102af6106b5565b34801561039b57600080fd5b506101466103aa366004610d50565b60009081526001602052604090205490565b3480156103c857600080fd5b506101796103d7366004610f7a565b6106de565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146104445760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b600080549081900361048a5760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b604482015260640161043b565b60008181526001602081905260409091208490556104a9908290610f95565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146105685760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c657200604482015260640161043b565b600054156105ae5760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b604482015260640161043b565b600055565b6105bb610763565b6105c482610808565b6105ce8282610810565b5050565b6000858152600160205260408120546105ee90868686866108d2565b9695505050505050565b6000610602610930565b5060008051602061100e83398151915290565b61061d610979565b61062760006109ab565b565b33806106336106b5565b6001600160a01b0316146106655760405163118cdaa760e01b81526001600160a01b038216600482015260240161043b565b61066e816109ab565b50565b6000807f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c1993005b546001600160a01b031692915050565b60006105ee86868686866108d2565b6000807f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c00610696565b6106e6610979565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b0319166001600160a01b038316908117825561072a610671565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a35050565b306001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614806107ea57507f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166107de60008051602061100e833981519152546001600160a01b031690565b6001600160a01b031614155b156106275760405163703e46dd60e11b815260040160405180910390fd5b61066e610979565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa92505050801561086a575060408051601f3d908101601f1916820190925261086791810190610fb6565b60015b61089257604051634c9c8ce360e01b81526001600160a01b038316600482015260240161043b565b60008051602061100e83398151915281146108c357604051632a87526960e21b81526004810182905260240161043b565b6108cd83836109e3565b505050565b6000858152600260209081526040808320548151601f8701849004840281018401909252858252916109259188918491908990899081908401838280828437600092019190915250899250610a39915050565b979650505050505050565b306001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146106275760405163703e46dd60e11b815260040160405180910390fd5b33610982610671565b6001600160a01b0316146106275760405163118cdaa760e01b815233600482015260240161043b565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b03191681556105ce82610a77565b6109ec82610ae8565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a2805115610a31576108cd8282610b4d565b6105ce610bc5565b60008385148015610a48575081155b8015610a5357508251155b15610a6057506001610a6f565b610a6c85848685610be4565b90505b949350505050565b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b806001600160a01b03163b600003610b1e57604051634c9c8ce360e01b81526001600160a01b038216600482015260240161043b565b60008051602061100e83398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080846001600160a01b031684604051610b6a9190610fcf565b600060405180830381855af49150503d8060008114610ba5576040519150601f19603f3d011682016040523d82523d6000602084013e610baa565b606091505b5091509150610bba858383610c8e565b925050505b92915050565b34156106275760405163b398979f60e01b815260040160405180910390fd5b600060208451610bf49190610feb565b15610c0157506000610a6f565b8351600003610c1257506000610a6f565b818560005b8651811015610c8157610c2b600284610feb565b600103610c4f57610c48610c428883016020015190565b83610ced565b9150610c68565b610c6582610c608984016020015190565b610ced565b91505b60019290921c91610c7a602082610f95565b9050610c17565b5090931495945050505050565b606082610ca357610c9e82610cf9565b610ce6565b8151158015610cba57506001600160a01b0384163b155b15610ce357604051639996b31560e01b81526001600160a01b038516600482015260240161043b565b50805b9392505050565b6000610ce68383610d22565b805115610d095780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b600060208284031215610d6257600080fd5b5035919050565b60008060408385031215610d7c57600080fd5b50508035926020909101359150565b80356001600160a01b0381168114610da257600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60008060408385031215610dd057600080fd5b610dd983610d8b565b9150602083013567ffffffffffffffff80821115610df657600080fd5b818501915085601f830112610e0a57600080fd5b813581811115610e1c57610e1c610da7565b604051601f8201601f19908116603f01168101908382118183101715610e4457610e44610da7565b81604052828152886020848701011115610e5d57600080fd5b8260208601602083013760006020848301015280955050505050509250929050565b60008083601f840112610e9157600080fd5b50813567ffffffffffffffff811115610ea957600080fd5b602083019150836020828501011115610ec157600080fd5b9250929050565b600080600080600060808688031215610ee057600080fd5b8535945060208601359350604086013567ffffffffffffffff811115610f0557600080fd5b610f1188828901610e7f565b96999598509660600135949350505050565b60005b83811015610f3e578181015183820152602001610f26565b50506000910152565b6020815260008251806020840152610f66816040850160208701610f23565b601f01601f19169190910160400192915050565b600060208284031215610f8c57600080fd5b610ce682610d8b565b80820180821115610bbf57634e487b7160e01b600052601160045260246000fd5b600060208284031215610fc857600080fd5b5051919050565b60008251610fe1818460208701610f23565b9190910192915050565b60008261100857634e487b7160e01b600052601260045260246000fd5b50069056fe360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca26469706673582212208a59ff38af63c8a0ca256bb007b725d98ab1c290599e8cdf87bcbf2a98add93164736f6c63430008190033'))

    def test_get_block(self):
        block = self.web3.eth.get_block('latest')
        self.assertEqual(block['number'], self.web3.eth.get_block_number())

        first_tx_receipt = self.web3.eth.get_transaction_receipt(self.first_tx_hash)
        block = self.web3.eth.get_block(first_tx_receipt['blockNumber'])
        self.assertEqual(block['hash'], first_tx_receipt['blockHash'])

        block = self.web3.eth.get_block(first_tx_receipt['blockHash'])
        self.assertEqual(block['hash'], first_tx_receipt['blockHash'])

    def test_get_transaction_count_block(self):
        # Test it with block number
        tx_count = self.web3.eth.get_block_transaction_count(1)
        self.assertEqual(tx_count, 3)
        block = self.web3.eth.get_block(1)
        # Test it with hash
        tx_count = self.web3.eth.get_block_transaction_count(block.hash)
        self.assertEqual(tx_count, 3)

    def test_get_transaction(self):
        tx = self.web3.eth.get_transaction(self.first_tx_hash)
        self.assertEqual(tx['hash'], self.first_tx_hash)
        self.assertEqual(tx['from'], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        self.assertEqual(tx['to'], "0x0000000000000000000000000000000000000000")
    
    def test_get_transaction_by_block(self):
        tx = self.web3.eth.get_transaction(self.first_tx_hash)
        block = self.web3.eth.get_block(tx['blockHash'])
        index = tx['transactionIndex']
        block_number = block['number']
        tx = self.web3.eth.get_transaction_by_block(block_number, index)
        self.assertEqual(tx['hash'], self.first_tx_hash)

    def test_get_transaction_receipt(self):
        receipt = self.web3.eth.get_transaction_receipt(self.first_tx_hash)
        self.assertEqual(receipt['transactionHash'], self.first_tx_hash)
        self.assertEqual(receipt['from'], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        self.assertEqual(receipt['to'], "0x0000000000000000000000000000000000000000")
        self.assertGreater(int(receipt['diffSize'], 16), 0)
        self.assertGreater(int(receipt['l1FeeRate'], 16), 0)

    def test_get_transaction_count(self):
        tx_count = self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        self.assertGreater(tx_count, 0)

    def test_call(self):
        selector = self.web3.keccak(text='SYSTEM_CALLER()')[:4]
        return_val = self.web3.eth.call({'value': 0, 'to': '0x3100000000000000000000000000000000000001', 'data': selector})
        self.assertEqual(return_val, HexBytes('0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead'))

    def test_create_access_list(self):        
        tx = {
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'to': "0x3100000000000000000000000000000000000002",
            'value': self.web3.to_wei(0.01, 'ether'),  
            'gas': 200000,
            'gasPrice': self.web3.to_wei(1, 'gwei'),
            'data': "0x8e19899e0000000000000000000000000000000000000000000000000000000000000000", # withdraw(bytes32), param is 0x0
            'nonce': self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            'chainId': 5655
        }
        access_list = self.web3.eth.create_access_list(tx)
        # Assert existence of the access list
        self.assertGreater(len(access_list), 1)

    def test_fee_history(self):
        fee_history = self.web3.eth.fee_history(1, 1)
        self.assertGreater(fee_history['gasUsedRatio'][0], 0)

    def test_estimate_gas(self):
        estimate = self.web3.eth.estimate_gas({
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'to': "0x0000000000000000000000000000000000000000",
            'value': self.web3.to_wei(1, 'ether'),
        })
        self.assertGreaterEqual(estimate, 21000) # Extra gas comes from L1 fee addition on top of 21000, 21000 is the default Ether transfer gas amount

    def test_get_logs(self):
        # OperatorUpdated event
        logs = self.web3.eth.get_logs({'fromBlock': 1, 'toBlock': 1, 'topics': ["0xfbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03"]})
        self.assertEqual(logs[0].address, "0x3100000000000000000000000000000000000002")
        # Operator is updated from 0x0 to deaddeaddeaddeaddeaddeaddeaddeaddeaddead address which is the system caller
        self.assertEqual(logs[0].data, HexBytes("0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead"))

    def test_contract_deploy(self):
        abi = [{"constant":True,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[{"name":"wad","type":"uint256"}],"name":"withdraw","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":False,"stateMutability":"view","type":"function"},{"constant":False,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":False,"stateMutability":"nonpayable","type":"function"},{"constant":False,"inputs":[],"name":"deposit","outputs":[],"payable":True,"stateMutability":"payable","type":"function"},{"constant":True,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"},{"payable":True,"stateMutability":"payable","type":"fallback"},{"anonymous":False,"inputs":[{"indexed":True,"name":"src","type":"address"},{"indexed":True,"name":"guy","type":"address"},{"indexed":False,"name":"wad","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"name":"src","type":"address"},{"indexed":True,"name":"dst","type":"address"},{"indexed":False,"name":"wad","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"name":"dst","type":"address"},{"indexed":False,"name":"wad","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":False,"inputs":[{"indexed":True,"name":"src","type":"address"},{"indexed":False,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}]
        initcode = "60606040526040805190810160405280600d81526020017f57726170706564204574686572000000000000000000000000000000000000008152506000908051906020019061004f9291906100c8565b506040805190810160405280600481526020017f57455448000000000000000000000000000000000000000000000000000000008152506001908051906020019061009b9291906100c8565b506012600260006101000a81548160ff021916908360ff16021790555034156100c357600080fd5b61016d565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061010957805160ff1916838001178555610137565b82800160010185558215610137579182015b8281111561013657825182559160200191906001019061011b565b5b5090506101449190610148565b5090565b61016a91905b8082111561016657600081600090555060010161014e565b5090565b90565b610c348061017c6000396000f3006060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b9578063095ea7b31461014757806318160ddd146101a157806323b872dd146101ca5780632e1a7d4d14610243578063313ce5671461026657806370a082311461029557806395d89b41146102e2578063a9059cbb14610370578063d0e30db0146103ca578063dd62ed3e146103d4575b6100b7610440565b005b34156100c457600080fd5b6100cc6104dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561010c5780820151818401526020810190506100f1565b50505050905090810190601f1680156101395780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561015257600080fd5b610187600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061057b565b604051808215151515815260200191505060405180910390f35b34156101ac57600080fd5b6101b461066d565b6040518082815260200191505060405180910390f35b34156101d557600080fd5b610229600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061068c565b604051808215151515815260200191505060405180910390f35b341561024e57600080fd5b61026460048080359060200190919050506109d9565b005b341561027157600080fd5b610279610b05565b604051808260ff1660ff16815260200191505060405180910390f35b34156102a057600080fd5b6102cc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b18565b6040518082815260200191505060405180910390f35b34156102ed57600080fd5b6102f5610b30565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561033557808201518184015260208101905061031a565b50505050905090810190601f1680156103625780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561037b57600080fd5b6103b0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610bce565b604051808215151515815260200191505060405180910390f35b6103d2610440565b005b34156103df57600080fd5b61042a600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610be3565b6040518082815260200191505060405180910390f35b34600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055503373ffffffffffffffffffffffffffffffffffffffff167fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c346040518082815260200191505060405180910390a2565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b505050505081565b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156106dc57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16141580156107b457507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414155b156108cf5781600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561084457600080fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a2757600080fd5b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501515610ab457600080fd5b3373ffffffffffffffffffffffffffffffffffffffff167f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65826040518082815260200191505060405180910390a250565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610bc65780601f10610b9b57610100808354040283529160200191610bc6565b820191906000526020600020905b815481529060010190602001808311610ba957829003601f168201915b505050505081565b6000610bdb33848461068c565b905092915050565b60046020528160005260406000206020528060005260406000206000915091505054815600a165627a7a72305820deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a0029"
        contract = self.web3.eth.contract(abi=abi, bytecode=initcode)
        tx = contract.constructor().build_transaction({
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'value': 0,
            'gas': 2000000,
            'gasPrice': self.web3.to_wei(1, 'gwei'),
            'nonce': self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            'chainId': 5655
        })
        signed_tx = self.web3.eth.account.sign_transaction(tx, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        weth_address = receipt['contractAddress']

        contract = self.web3.eth.contract(address=weth_address, abi=abi)
        self.assertEqual(contract.functions.name().call(), "Wrapped Ether")
        self.assertEqual(contract.functions.balanceOf("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").call(), 0)

        # Deposit 1 Ether
        tx = contract.functions.deposit().build_transaction({
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'value': self.web3.to_wei(1, 'ether'),
            'gas': 2000000,
            'gasPrice': self.web3.to_wei(1, 'gwei'),
            'nonce': self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            'chainId': 5655
        })
        signed_tx = self.web3.eth.account.sign_transaction(tx, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        # Check if 1 WETH is minted
        self.assertEqual(contract.functions.balanceOf("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").call(), self.web3.to_wei(1, 'ether'))

    def test_call_errors_correctly(self):
        try:
            selector = self.web3.keccak(text='ERRONEUS_FUNC()')[:4]
            self.web3.eth.call({'value': 0, 'to': '0x3100000000000000000000000000000000000001', 'data': selector})
            self.fail("Expected call to fail, but it succeeded.")
        except Exception as e:
            self.assertEqual(str(e), "('execution reverted', 'no data')")

    def test_send_raw_transaction_reverts_correctly(self):
        tx = {
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'to': "0x3100000000000000000000000000000000000002",
            'value': self.web3.to_wei(0.9, 'ether'),  
            'gas': 200000,
            'gasPrice': self.web3.to_wei(1, 'gwei'),
            'data': "0x8e19899e0000000000000000000000000000000000000000000000000000000000000000", # withdraw(bytes32), param is 0x0
            'nonce': self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            'chainId': 5655
        }
        signed_tx = self.web3.eth.account.sign_transaction(tx, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        self.assertEqual(receipt['status'], 0)

    def test_call_errors_correctly_on_withdraw(self):
        tx = {
            'from': "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            'to': "0x3100000000000000000000000000000000000002",
            'value': self.web3.to_wei(0.9, 'ether'),  
            'gas': 200000,
            'gasPrice': self.web3.to_wei(1, 'gwei'),
            'data': "0x8e19899e0000000000000000000000000000000000000000000000000000000000000000", # withdraw(bytes32), param is 0x0
            'nonce': self.web3.eth.get_transaction_count("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            'chainId': 5655
        }
        try:
            self.web3.eth.call(tx)
            self.fail("Expected call to fail, but it succeeded.")
        except Exception as e:
            self.assertEqual(str(e), "('execution reverted: revert: Invalid withdraw amount', '0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000017496e76616c696420776974686472617720616d6f756e74000000000000000000')")


    def test_get_transaction_false_hash(self):
        try:
            self.web3.eth.get_transaction("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            self.fail("Expected get_transaction to fail, but it succeeded.")
        except Exception as e:
            self.assertEqual(str(e), "Transaction with hash: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' not found.")

    def test_get_block_false_hash(self):
        try:
            self.web3.eth.get_block("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            self.fail("Expected get_block to fail, but it succeeded.")
        except Exception as e:
            self.assertEqual(str(e), "Block with id: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' not found.")

    def test_get_transaction_receipt_false_hash(self):
        try:
            self.web3.eth.get_transaction_receipt("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            self.fail("Expected get_transaction_receipt to fail, but it succeeded.")
        except Exception as e:
            self.assertEqual(str(e), "Transaction with hash: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' not found.")

    def test_get_logs_false_hash(self):
        logs = self.web3.eth.get_logs({'fromBlock': 1, 'toBlock': 1, 'topics': ["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]})
        self.assertEqual(logs, [])

if __name__ == '__main__':
    unittest.main()