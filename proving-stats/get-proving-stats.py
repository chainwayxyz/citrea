#!/usr/bin/env python3

import time
import json
import requests
import sys

COMMITMENTS = [1, 2]
PROVER_RPC_URL = "http://localhost:12346"

# --- Wait until commitments are proven ---
def wait_for_proofs()->dict:
    def query(commitment_id):
        payload = {
            "jsonrpc": "2.0",
            "method": "batchProver_getProvingJobOfCommitment",
            "params": [commitment_id],
            "id": 1
        }
        try:
            res = requests.post(PROVER_RPC_URL, json=payload, timeout=5)
            res.raise_for_status()
            result = res.json().get("result")
            return result
        except Exception as e:
            print(f"RPC error for commitment {commitment_id}: {e}")
            return None
        
    def query_until_proven(commitment_id):
        start_time = time.time()
        while True:
            job_response = query(commitment_id)
            if job_response and job_response.get("proof"):
                return job_response.get("proof")
            elif (time.time() - start_time) > 600: # 10 minutes in seconds
                raise TimeoutError(f"Timeout: Commitment {commitment_id} not proven within 10 minutes.")
            time.sleep(5)

    results = []
    for commitment_id in COMMITMENTS:
        print(f"Waiting for proof of commitment {commitment_id}...")
        results.append(query_until_proven(commitment_id))
    return results

def extract_cycles_from_job_responses(proof_responses):
    """Extract cycles from the proving session info in proof responses (Local prover format)"""
    total = user = paging = reserved = 0
    
    for proof in proof_responses:
        info = proof["info"]
        local_info = info["Local"]

        total += local_info["total_cycles"]
        user += local_info["user_cycles"]
        paging += local_info["paging_cycles"]
        reserved += local_info["reserved_cycles"]
    return {
        "Total Cycles": total,
        "User Cycles": user,
        "Paging Cycles": paging,
        "Reserved Cycles": reserved,
    }

def state_diff_size(state_diff):
    size = 0
    for key, value in state_diff.items():
        size += len(key) // 2
        if value:
            size += len(value) // 2
    return size # in bytes


def main():
    if len(sys.argv) < 2:
        print("Usage: python get_proof_data.py <output_file>")
        sys.exit(1)
    output_file = sys.argv[1]

    # Wait for proofs to be ready
    proof_responses = wait_for_proofs()

    # Extract cycles from RPC responses
    cycles = extract_cycles_from_job_responses(proof_responses)
    print(f"Extracted cycles: {cycles}")

    # Extract state diffs
    state_diffs = map(lambda proof: proof["proofOutput"]["stateDiff"], proof_responses)
    total_diff_size = sum(
        map(state_diff_size, state_diffs)
    )
    print(f"Total state diff size: {total_diff_size} bytes")

    with open(output_file, 'w') as out_f:
        output_data = {**cycles, "State Diff Size (bytes)": total_diff_size}
        json.dump(output_data, out_f, indent=4)

if __name__ == "__main__":
    main()
