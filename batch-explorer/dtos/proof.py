from pydantic import BaseModel


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
    proof_type: str


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
    proof_type: str
