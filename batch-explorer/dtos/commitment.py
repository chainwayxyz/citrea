from pydantic import BaseModel


class CommitmentResponse(BaseModel):
    l1_tx_id: str
    l1_start_hash: str
    l1_end_hash: str
    l1_start_hash_mempool_url: str
    l1_end_hash_mempool_url: str
    l2_start_height: int
    l2_end_height: int
    l2_start_height_block_exp_url: str
    l2_end_height_block_exp_url: str
    merkle_root: str
    status: str


class SequencerCommitment(BaseModel):
    l1_start_height: int
    l1_end_height: int
    l1_tx_id: bytes
    l1_start_hash: bytes
    l1_end_hash: bytes
    l2_start_height: int
    l2_end_height: int
    merkle_root: bytes
    status: str


"""
CREATE TABLE IF NOT EXISTS proof (
    id                          SERIAL PRIMARY KEY,
    l1_tx_id                    BYTEA NOT NULL,
    proof_data                  BYTEA NOT NULL,
    initial_state_root          BYTEA NOT NULL,
    final_state_root            BYTEA NOT NULL,
    state_diff                  BYTEA NOT NULL,
    da_slot_hash                BYTEA NOT NULL,
    sequencer_public_key        BYTEA NOT NULL,
    sequencer_da_public_key     BYTEA NOT NULL,
    validity_condition          BYTEA NOT NULL
);
"""


class ProofData(BaseModel):
    l1_tx_id: bytes
    proof_data: bytes
    initial_state_root: bytes
    final_state_root: bytes
    state_diff: bytes
    da_slot_hash: bytes
    sequencer_public_key: bytes
    sequencer_da_public_key: bytes
    validity_condition: bytes


class ProofDataResponse(BaseModel):
    l1_tx_id: str
    proof_data: str
    initial_state_root: str
    final_state_root: str
    state_diff: str
    da_slot_hash: str
    sequencer_public_key: str
    sequencer_da_public_key: str
    validity_condition: str
