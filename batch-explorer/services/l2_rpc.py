import httpx
from config import CONFIG
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.types import BlockIdentifier


class L2RpcClient:
    def __init__(self):
        self.url = CONFIG.l2_rpc_url
        self.w3 = AsyncWeb3(AsyncHTTPProvider(self.url))

    async def get_l2_block_by_hash(self, hash: str):
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [hash, False],
            "id": 1,
        }

        # send request to l2 rpc with web3py
        try:
            return await self.w3.eth.get_block(hash)
        except Exception as e:
            raise e

        
