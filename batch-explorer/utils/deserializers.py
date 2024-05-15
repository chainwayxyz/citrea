from dtos.commitment import SequencerCommitment, CommitmentResponse
from config import CONFIG


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
        responses.append(
            CommitmentResponse(
                l1_tx_id=f"{CONFIG.mempool_space_url}/tx/{row[3].decode("utf-8")}",
                l1_start_hash=row[4].hex(),
                l1_end_hash=row[5].hex(),
                l1_start_hash_mempool_url=f"{CONFIG.mempool_space_url}/block/{row[4].hex()}",
                l1_end_hash_mempool_url=f"{CONFIG.mempool_space_url}/block/{row[5].hex()}",
                l2_start_height=row[6],
                l2_end_height=row[7],
                l2_start_height_block_exp_url=f"{CONFIG.blockscout_url}/block/{row[6]}",
                l2_end_height_block_exp_url=f"{CONFIG.blockscout_url}/block/{row[7]}",
                merkle_root=row[8].hex(),
                status=row[9],
            )
        )
    return responses
