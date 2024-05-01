import httpx
from config import CONFIG


class L2RpcClient:
    def __init__(self):
        self.url = CONFIG.l2_rpc_url

    async def get_l2_block_by_hash(self, hash: str):
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [hash, False],
            "id": 1,
        }
        async with httpx.AsyncClient() as client:
            response = await client.post("https://www.example.com/", json=payload)
            if response.status_code >= 200 and response.status_code <= 299:
                try:
                    return response.json()
                except Exception as e:
                    return None
            else:
                response.raise_for_status()
