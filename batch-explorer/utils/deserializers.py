from dtos.commitment import (
    SequencerCommitment,
    CommitmentResponse,
)
from dtos.proof import (
    ProofData,
    ProofDataResponse,
)
from config import CONFIG


def bytes_to_hex(bytes_):
    return str(bytes_)[2:-1]


def deserialize_commitments(rows):
    commtiments = []
    for row in rows:
        commtiments.append(
            SequencerCommitment(
                l1_start_height=row[1],
                l1_end_height=row[2],
                l1_tx_id=row[3],
                l1_start_hash=row[4],
                l1_end_hash=row[5],
                l2_start_height=row[6],
                l2_end_height=row[7],
                merkle_root=row[8],
                status=row[9],
            )
        )
    return commtiments


def deserialize_to_commitment_response(rows):
    responses = []
    for row in rows:
        decoded = row[3].decode("utf-8")
        responses.append(
            CommitmentResponse(
                l1_tx_id=f"{CONFIG.mempool_space_url}/tx/{decoded}",
                l1_start_hash=bytes_to_hex(row[4]),
                l1_end_hash=bytes_to_hex(row[5]),
                l1_start_hash_mempool_url=f"{CONFIG.mempool_space_url}/block/{bytes_to_hex(row[4])}",
                l1_end_hash_mempool_url=f"{CONFIG.mempool_space_url}/block/{bytes_to_hex(row[5])}",
                l2_start_height=row[6],
                l2_end_height=row[7],
                l2_start_height_block_exp_url=f"{CONFIG.blockscout_url}/block/{row[6]}",
                l2_end_height_block_exp_url=f"{CONFIG.blockscout_url}/block/{row[7]}",
                merkle_root=bytes_to_hex(row[8]),
                status=row[9],
            )
        )
    return responses


def deserialize_proof_data(rows):
    proofs = []
    for row in rows:
        proofs.append(
            ProofData(
                l1_tx_id=row[1],
                proof_data=row[2],
                initial_state_root=row[3],
                final_state_root=row[4],
                state_diff=row[5],
                da_slot_hash=row[6],
                sequencer_public_key=row[7],
                sequencer_da_public_key=row[8],
                validity_condition=row[9],
                proof_type=row[10],
            )
        )
    return proofs


def deserialize_to_proof_data_response(rows):
    proofs = []
    for row in rows:
        proofs.append(
            ProofDataResponse(
                l1_tx_id=bytes_to_hex(row[1]),
                proof_data=bytes_to_hex(row[2]),
                initial_state_root=bytes_to_hex(row[3]),
                final_state_root=bytes_to_hex(row[4]),
                state_diff=bytes_to_hex(row[5]),
                da_slot_hash=bytes_to_hex(row[6]),
                sequencer_public_key=bytes_to_hex(row[7]),
                sequencer_da_public_key=bytes_to_hex(row[8]),
                validity_condition=bytes_to_hex(row[9]),
                proof_type=row[10],
            )
        )
    return proofs
