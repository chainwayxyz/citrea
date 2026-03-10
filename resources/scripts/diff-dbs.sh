#!/usr/bin/env bash
#
# Rocksdb database diff script
# ----------------------------
#
# Lists column families in each databases, hashes each CF's dump output
# and compares the hashes.
#
# Usage:
#   ./scripts/diff-dbs.sh <db_path_1> <db_path_2>
#
# Arguments are the top-level paths containing ledger/, state/, native/ sub dirs.
# Typically: resources/dbs/ or similar.

# Requirements:
#   - rocksdb_ldb (or ldb) — RocksDB CLI tool
#   - shasum or sha256sum

set -euo pipefail

# Resolve `ldb` tool
LDB="rocksdb_ldb"

if ! command -v "$LDB" &>/dev/null; then
    LDB="ldb"
    if ! command -v "$LDB" &>/dev/null; then
        echo "Error: neither 'rocksdb_ldb' nor 'ldb' found. RocksDB tools are required" >&2
        exit 1
    fi
fi

# Resolve hasher
if command -v sha256sum &>/dev/null; then
    SHA256="sha256sum"
elif command -v shasum &>/dev/null; then
    SHA256="shasum -a 256"
else
    echo "Error: neither 'sha256sum' nor 'shasum' found." >&2
    exit 1
fi

if [ $# -ne 2 ]; then
    echo "Usage: $0 <node_db_path_1> <node_db_path_2>" >&2
    echo "" >&2
    echo "Arguments are top-level DB directories containing ledger/, state/, native/ sub dirs." >&2
    exit 1
fi

DB1="$1"
DB2="$2"

for path in "$DB1" "$DB2"; do
    if [ ! -d "$path" ]; then
        echo "Error: '$path' is not a directory" >&2
        exit 1
    fi
done

# Verify `ledger`, `state` and `native` dbs exist in both paths
for db in ledger state native; do
    for path in "$DB1" "$DB2"; do
        if [ ! -d "$path/$db" ]; then
            echo "Error: '$path/$db' not found." >&2
            echo "Make sure you're passing the parent directory." >&2
            exit 1
        fi
    done
done

# Parse column families from ldb output
list_cfs() {
    local db_path="$1"
    "$LDB" --db="$db_path" list_column_families 2>/dev/null \
        | grep -o '{.*}' \
        | tr -d '{}' \
        | tr ',' '\n' \
        | sed 's/^ *//;s/ *$//' \
        | grep -v '^$'
}

# Hash a CF's dump output
hash_cf() {
    local db_path="$1"
    local cf="$2"
    "$LDB" --db="$db_path" --column_family="$cf" dump 2>/dev/null \
        | $SHA256 \
        | awk '{print $1}'
}

DBS=("ledger" "state" "native")
found_diff=0

for db in "${DBS[@]}"; do
    path1="$DB1/$db"
    path2="$DB2/$db"

    cfs1=$(list_cfs "$path1" | sort)
    cfs2=$(list_cfs "$path2" | sort)
    cf_count1=$(echo "$cfs1" | grep -c -v '^$' || true)
    cf_count2=$(echo "$cfs2" | grep -c -v '^$' || true)
    echo "=== $db (DB1: $cf_count1 cfs, DB2: $cf_count2 cfs) ==="

    if [ "$cfs1" != "$cfs2" ]; then
        echo "  COLUMN FAMILY MISMATCH"
        only1=$(comm -23 <(printf '%s\n' "$cfs1") <(printf '%s\n' "$cfs2") | sed '/^$/d' || true)
        only2=$(comm -13 <(printf '%s\n' "$cfs1") <(printf '%s\n' "$cfs2") | sed '/^$/d' || true)
        if [ -n "$only1" ]; then
            echo "    Only in DB1:"
            echo "$only1" | sed 's/^/      - /'
        fi
        if [ -n "$only2" ]; then
            echo "    Only in DB2:"
            echo "$only2" | sed 's/^/      - /'
        fi
        found_diff=1
        continue
    fi

    while IFS= read -r cf; do
        [ -z "$cf" ] && continue

        echo -n "  Hashing $db/$cf..."

        hash1=$(hash_cf "$path1" "$cf")
        hash2=$(hash_cf "$path2" "$cf")

        if [ "$hash1" != "$hash2" ]; then
            echo " DIFF"
            echo "    DB1: $hash1"
            echo "    DB2: $hash2"
            found_diff=1
        else
            echo " OK"
        fi
    done <<< "$cfs1"
done

if [ $found_diff -eq 0 ]; then
    echo "SUCCESS: All databases match."
else
    echo "FAILED: databases differ."
fi

exit $found_diff
