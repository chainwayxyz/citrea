#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time
import uuid
import os
import re
import json
import signal
import requests
from pathlib import Path
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
            return result.get("proof")
        except Exception as e:
            print(f"RPC error for commitment {commitment_id}: {e}")
            return None
        
    def query_until_proven(commitment_id):
        start_time = time.time()
        while True:
            proof = query(commitment_id)
            if proof:
                return proof
            elif (time.time() - start_time) > 600: # 10 minutes in seconds
                raise TimeoutError(f"Timeout: Commitment {commitment_id} not proven within 10 minutes.")
                return None
            time.sleep(5)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(query_until_proven, commitment_id): commitment_id for commitment_id in COMMITMENTS}
        results = []
        for future in as_completed(futures):
            proof = future.result()
            results.append(proof)
        return results

# --- Parse log lines ---
def extract_cycles(log_lines):
    pattern = re.compile(r"SessionStats\s*{[^}]*?total_cycles:\s*(\d+),\s*user_cycles:\s*(\d+),\s*paging_cycles:\s*(\d+),\s*reserved_cycles:\s*(\d+)")
    total = user = paging = reserved = 0
    matched = 0
    for line in log_lines:
        match = pattern.search(line)
        if match:
            matched += 1

            total += int(match.group(1))
            user += int(match.group(2))
            paging += int(match.group(3))
            reserved += int(match.group(4))

    assert matched == 2, f"Expected exactly two lines with cycle counts, found {matched}."
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
    if len(sys.argv) < 3:
        print("Usage: python get_proof_data.py <batch_prover_stdout_file> <output_file>")
        sys.exit(1)
    batch_prover_stdout_file = sys.argv[1]
    output_file = sys.argv[2]

    # Wait for proofs to be ready
    proofs = wait_for_proofs()

    state_diffs = map(lambda proof: proof["proofOutput"]["stateDiff"], proofs)
    total_diff_size = sum(
        map(state_diff_size, state_diffs)
    )
    print(f"Total state diff size: {total_diff_size} bytes")

    # Read log lines from the batch prover stdout file
    with open(batch_prover_stdout_file, 'r') as log_f:
        log_lines = log_f.readlines()
    cycles = extract_cycles(log_lines)
    print(f"Extracted cycles: {cycles}")

    with open(output_file, 'w') as out_f:
        output_data = {**cycles, "State Diff Size (bytes)": total_diff_size}
        json.dump(output_data, out_f, indent=4)

if __name__ == "__main__":
    main()
