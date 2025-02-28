//! A primitive to merge two Stateful StateDiffs

use std::collections::BTreeMap;

use alloy_primitives::U256;

use super::compression::{
    CodeHashChange, CompressionAbsent, CompressionAdd, CompressionAddInlined, CompressionSub,
    CompressionTransform, SlotChange,
};
use super::{
    AccountChange, LatestBlockHashes, StatefulStateDiff, StorageChange, UnparsedStateDiff,
};

/// An operation to merge two values into one
pub(crate) trait Merge {
    /// Produce a value that is a merge of two given values
    fn merge(self, other: Self) -> Self;
}

// merge None Some(x) = Some(x)
// merge _ None = None
// merge Some(a) Some(b) = a.merge(b)
impl<T: Merge> Merge for Option<T> {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Some(left), Some(right)) => Some(left.merge(right)),
            (_, right @ Some(_)) => right,
            (_, None) => None,
        }
    }
}

impl Merge for SlotChange {
    /// Combine two changes into one which gives the same affect.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (_left, right @ Self::Transform(_)) => right,
            (_left, right @ Self::NoCompression(_)) => right,

            // Transform(x) + Add/Sub(y) = Transform/NoCompression(x+-y)
            (Self::Transform(left), Self::Add(right)) => {
                let left = left.diff;
                let (diff, _overflowed) = left.overflowing_add(right.diff);
                let size = diff.byte_len() as u8;
                if size < 31 {
                    Self::Transform(CompressionTransform { diff, size })
                } else {
                    Self::NoCompression(CompressionAbsent { diff })
                }
            }
            (Self::Transform(left), Self::Sub(right)) => {
                let left = left.diff;
                let (diff, _overflowed) = left.overflowing_sub(right.diff);
                let size = diff.byte_len() as u8;
                if size < 31 {
                    Self::Transform(CompressionTransform { diff, size })
                } else {
                    Self::NoCompression(CompressionAbsent { diff })
                }
            }
            (Self::Transform(left), Self::AddInlined(right)) => {
                let left = left.diff;
                let (diff, _overflowed) = left.overflowing_add(U256::from(right.diff));
                let size = diff.byte_len() as u8;
                if size < 31 {
                    Self::Transform(CompressionTransform { diff, size })
                } else {
                    Self::NoCompression(CompressionAbsent { diff })
                }
            }

            // NoCompression(x) + Add/Sub(y) = Transform/NoCompression(x+-y)
            (Self::NoCompression(left), Self::Add(right)) => {
                let left = left.diff;
                let (diff, _overflowed) = left.overflowing_add(right.diff);
                let size = diff.byte_len() as u8;
                if size < 31 {
                    Self::Transform(CompressionTransform { diff, size })
                } else {
                    Self::NoCompression(CompressionAbsent { diff })
                }
            }
            (Self::NoCompression(left), Self::Sub(right)) => {
                let left = left.diff;
                let (diff, _overflowed) = left.overflowing_sub(right.diff);
                let size = diff.byte_len() as u8;
                if size < 31 {
                    Self::Transform(CompressionTransform { diff, size })
                } else {
                    Self::NoCompression(CompressionAbsent { diff })
                }
            }
            (Self::NoCompression(left), Self::AddInlined(right)) => {
                let left = left.diff;
                let (diff, _overflowed) = left.overflowing_add(U256::from(right.diff));
                let size = diff.byte_len() as u8;
                if size < 31 {
                    Self::Transform(CompressionTransform { diff, size })
                } else {
                    Self::NoCompression(CompressionAbsent { diff })
                }
            }

            // Add(x) + Add(y) = Add(x+y)
            (Self::Add(left), Self::Add(right)) => {
                let (diff, _overflowed) = left.diff.overflowing_add(right.diff);
                if let Ok(diff) = diff.try_into() {
                    if diff < 32 {
                        return Self::AddInlined(CompressionAddInlined { diff });
                    }
                }
                let size = diff.byte_len() as u8;
                Self::Add(CompressionAdd { diff, size })
            }
            (Self::AddInlined(left), Self::AddInlined(right)) => {
                let diff = left.diff + right.diff;
                let diff = U256::from(diff);
                if let Ok(diff) = diff.try_into() {
                    if diff < 32 {
                        return Self::AddInlined(CompressionAddInlined { diff });
                    }
                }
                let size = diff.byte_len() as u8;
                Self::Add(CompressionAdd { diff, size })
            }
            (Self::Add(big), Self::AddInlined(small))
            | (Self::AddInlined(small), Self::Add(big)) => {
                let (diff, _overflowed) = big.diff.overflowing_add(U256::from(small.diff));
                if let Ok(diff) = diff.try_into() {
                    if diff < 32 {
                        return Self::AddInlined(CompressionAddInlined { diff });
                    }
                }
                let size = diff.byte_len() as u8;
                Self::Add(CompressionAdd { diff, size })
            }

            // Sub(x) + Sub(y) = Sub(x+y)
            (Self::Sub(left), Self::Sub(right)) => {
                let (diff, _overflowed) = left.diff.overflowing_add(right.diff);
                // TODO SubInlined
                let size = diff.byte_len() as u8;
                Self::Sub(CompressionSub { diff, size })
            }

            // Add(x) + Sub(y) = Add(x-y)
            (Self::Add(left), Self::Sub(right)) => {
                let (diff, _overflowed) = left.diff.overflowing_sub(right.diff);
                if let Ok(diff) = diff.try_into() {
                    if diff < 32 {
                        return Self::AddInlined(CompressionAddInlined { diff });
                    }
                }
                let size = diff.byte_len() as u8;
                Self::Add(CompressionAdd { diff, size })
            }
            // Sub(x) + Add(y) = Sub(x-y)
            (Self::Sub(left), Self::Add(right)) => {
                let (diff, _overflowed) = left.diff.overflowing_sub(right.diff);
                // TODO SubInlined
                let size = diff.byte_len() as u8;
                Self::Sub(CompressionSub { diff, size })
            }

            (Self::Sub(big), Self::AddInlined(small))
            | (Self::AddInlined(small), Self::Sub(big)) => {
                let (diff, _overflowed) = big.diff.overflowing_sub(U256::from(small.diff));
                // TODO SubInlined
                let size = diff.byte_len() as u8;
                Self::Sub(CompressionSub { diff, size })
            }
        }
    }
}

impl Merge for CodeHashChange {
    /// Combine two changes into one which gives the same affect.
    fn merge(self, right: Self) -> Self {
        match (self, right) {
            (_, Self::Removed) => Self::Removed,
            (_, set @ Self::Set(_)) => set,
            (op, Self::Same) => op,
        }
    }
}

impl Merge for AccountChange {
    fn merge(self, other: Self) -> Self {
        Self {
            balance: self.balance.merge(other.balance),
            nonce: self.nonce.merge(other.nonce),
            code_hash: self.code_hash.merge(other.code_hash),
        }
    }
}

impl Merge for StorageChange {
    fn merge(self, other: Self) -> Self {
        StorageChange {
            storage: self.storage.merge(other.storage),
        }
    }
}

// if exists self[k] = old for each (k, new) in other,
//    then self[k] = old.merge(new)
// else self[k] = new
impl<K: Ord, V: Clone + Merge> Merge for BTreeMap<K, V> {
    fn merge(mut self, other: Self) -> Self {
        use std::collections::btree_map::Entry;
        for (rk, rv) in other {
            match self.entry(rk) {
                Entry::Vacant(entry) => {
                    entry.insert(rv);
                }
                Entry::Occupied(mut entry) => {
                    let lv = entry.get().clone();
                    entry.insert(lv.merge(rv));
                }
            }
        }
        self
    }
}

// Convert them to BTreeMap<K, V>, merge and convert back to Vec<(K, V)>
fn merge_vec_tuples<K: Ord, V: Clone + Merge>(
    left: Vec<(K, V)>,
    right: Vec<(K, V)>,
) -> Vec<(K, V)> {
    let left = BTreeMap::from_iter(left);
    let right: BTreeMap<_, _> = BTreeMap::from_iter(right);
    let res = left.merge(right);
    res.into_iter().collect()
}

// Concat vectors
fn merge_concat_vec<T>(mut left: Vec<T>, right: Vec<T>) -> Vec<T> {
    left.extend(right);
    left
}

fn merge_accounts_count(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (Some(_left), Some(right)) => {
            // This is the new value
            Some(right)
        }
        (None, Some(right)) => Some(right),
        (Some(left), None) => {
            // Because there could be no new accounts added so there is no change at all
            // That's why we need to keep the previous value
            Some(left)
        }
    }
}

fn merge_block_hashes(
    left: Option<LatestBlockHashes>,
    right: Option<LatestBlockHashes>,
) -> Option<LatestBlockHashes> {
    match (left, right) {
        (None, None) => None,
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (Some(left), Some(right)) => Some(LatestBlockHashes {
            starting_block_number: left.starting_block_number,
            block_hashes: merge_concat_vec(left.block_hashes, right.block_hashes),
        }),
    }
}

fn merge_unparsed(left: UnparsedStateDiff, right: UnparsedStateDiff) -> UnparsedStateDiff {
    let mut res: BTreeMap<_, _> = BTreeMap::from_iter(left);
    res.extend(right);
    res.into_iter().collect()
}

impl Merge for StatefulStateDiff {
    fn merge(self, other: Self) -> Self {
        Self {
            evm_accounts_prefork2: self
                .evm_accounts_prefork2
                .merge(other.evm_accounts_prefork2),
            evm_storage_prefork2: self.evm_storage_prefork2.merge(other.evm_storage_prefork2),
            evm_accounts: merge_vec_tuples(self.evm_accounts, other.evm_accounts),
            evm_account_address: merge_concat_vec(
                self.evm_account_address,
                other.evm_account_address,
            ),
            evm_account_count: merge_accounts_count(
                self.evm_account_count,
                other.evm_account_count,
            ),
            evm_storage: merge_vec_tuples(self.evm_storage, other.evm_storage),
            evm_latest_block_hashes: merge_block_hashes(
                self.evm_latest_block_hashes,
                other.evm_latest_block_hashes,
            ),
            unparsed: merge_unparsed(self.unparsed, other.unparsed),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{b256, B256, U256};

    use super::Merge;
    use crate::stateful_statediff::compression::{
        compress_two_best_strategy, compress_two_code_hash, CodeHashChange, CompressionAddInlined,
        SlotChange,
    };

    // calc final change of a given slot value:
    // - a1 a2 a3 a4...
    // - change12 change23 change34...
    // return change12.merge(change23).merge(change34)...
    fn calc_slot_change(slot_values: &[U256]) -> SlotChange {
        let changes: Vec<_> = slot_values
            .windows(2)
            .map(|s| {
                let [x, y] = s else {
                    panic!("size must be exactly 2 elems")
                };
                compress_two_best_strategy(*x, *y)
            })
            .collect();
        changes.into_iter().fold(
            SlotChange::AddInlined(CompressionAddInlined { diff: 0 }),
            |init, elem| init.merge(elem),
        )
    }

    fn apply_slot_change(val: U256, change: SlotChange) -> U256 {
        match change {
            SlotChange::Add(op) => val.overflowing_add(op.diff).0,
            SlotChange::AddInlined(op) => val.overflowing_add(U256::from(op.diff)).0,
            SlotChange::Sub(op) => val.overflowing_sub(op.diff).0,
            SlotChange::NoCompression(op) => op.diff,
            SlotChange::Transform(op) => op.diff,
        }
    }

    #[test]
    fn compress_slot_1() {
        let nums = vec![
            U256::from(0),
            U256::from(1),
            U256::from(5),
            U256::from(35),
            U256::from(34),
        ];
        let final_change = calc_slot_change(&nums);

        let first = *nums.first().unwrap();
        let last = *nums.last().unwrap();

        assert_eq!(last, apply_slot_change(first, final_change));
    }

    #[test]
    fn compress_slot_2() {
        let nums = vec![
            U256::from_limbs([u64::MAX / 2, u64::MAX / 2, u64::MAX / 2, u64::MAX / 2]),
            U256::from(135),
        ];
        let final_change = calc_slot_change(&nums);

        let first = *nums.first().unwrap();
        let last = *nums.last().unwrap();

        assert_eq!(last, apply_slot_change(first, final_change));
    }

    // calc final change of a given code_hash value:
    // - a1 a2 a3 a4...
    // - change12 change23 change34...
    // return change12.merge(change23).merge(change34)...
    fn calc_code_change(slot_values: &[Option<B256>]) -> CodeHashChange {
        let changes: Vec<_> = slot_values
            .windows(2)
            .map(|s| {
                let [x, y] = s else {
                    panic!("size must be exactly 2 elems")
                };
                compress_two_code_hash(*x, *y)
            })
            .collect();
        changes
            .into_iter()
            .fold(CodeHashChange::Removed, |init, elem| init.merge(elem))
    }

    fn apply_code_change(val: Option<B256>, change: CodeHashChange) -> Option<B256> {
        match (val, change) {
            (_, CodeHashChange::Removed) => None,
            (None, CodeHashChange::Same) => None,
            (Some(c), CodeHashChange::Same) => Some(c),
            (_, CodeHashChange::Set(c)) => Some(c),
        }
    }

    #[test]
    fn compress_code_1() {
        let nums = vec![None];
        let final_change = calc_code_change(&nums);

        let first = *nums.first().unwrap();
        let last = *nums.last().unwrap();

        assert_eq!(last, apply_code_change(first, final_change));
    }

    #[test]
    fn compress_code_2() {
        let nums = vec![
            Some(b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )),
            None,
            Some(b256!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )),
        ];
        let final_change = calc_code_change(&nums);

        let first = *nums.first().unwrap();
        let last = *nums.last().unwrap();

        assert_eq!(last, apply_code_change(first, final_change));
    }
}
