from pydantic import BaseModel


class CommitmentResponse(BaseModel):
    l1_tx_id: str
    l1_start_hash_mempool_url: str
    l1_end_hash_mempool_url: str
    l2_start_height_block_exp_url: str
    l2_end_height_block_exp_url: str
    merkle_root: str
    status: str


class SequencerCommitment(BaseModel):
    l1_start_height: int
    l1_end_height: int
    l1_tx_id: str
    l1_start_hash: str
    l1_end_hash: str
    l2_start_height: int
    l2_end_height: int
    merkle_root: str
    status: str
