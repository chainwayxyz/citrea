// Originally written in 2019 by Matter Labs. Lisence: MIT/APACHE.

use alloy_primitives::{B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};

/// diff(a, b) = Add(a+b)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressionAdd {
    diff: U256,
    size: u8,
}

impl CompressionAdd {
    fn new(prev_value: U256, new_value: U256) -> Option<Self> {
        let (diff, _overflowed) = new_value.overflowing_sub(prev_value);
        let size = diff.byte_len() as u8;

        if size < 31 {
            Some(Self { diff, size })
        } else {
            None
        }
    }
}

/// A special case when Add(x) for x <= 31 to fit into 1 serialized byte
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressionAddInlined {
    diff: u8,
}

impl CompressionAddInlined {
    fn new(prev_value: U256, new_value: U256) -> Option<Self> {
        let (diff, _overflowed) = new_value.overflowing_sub(prev_value);

        if let Ok(diff) = diff.try_into() {
            if diff < 32 {
                return Some(Self { diff });
            }
        }
        None
    }
}

/// diff(a, b) = Sub(a - b)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressionSub {
    diff: U256,
    size: u8,
}

impl CompressionSub {
    fn new(prev_value: U256, new_value: U256) -> Option<Self> {
        let (diff, _overflowed) = prev_value.overflowing_sub(new_value);
        let size = diff.byte_len() as u8;

        if size < 31 {
            Some(Self { diff, size })
        } else {
            None
        }
    }
}

/// Only try to remove leading zeroes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressionTransform {
    diff: U256,
    size: u8,
}

impl CompressionTransform {
    fn new(new_value: U256) -> Option<Self> {
        let diff = new_value;
        let size = diff.byte_len() as u8;

        if size < 31 {
            Some(Self { diff, size })
        } else {
            None
        }
    }
}

/// It's a special case when we store diff as is (32 bytes)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompressionAbsent {
    diff: U256,
}

impl CompressionAbsent {
    fn new(new_value: U256) -> Self {
        let diff = new_value;

        Self { diff }
    }
}

/// All possible diffs of a slot of U256
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlotChange {
    /// Add
    Add(CompressionAdd),
    /// AddInlined
    AddInlined(CompressionAddInlined),
    /// Sub
    Sub(CompressionSub),
    /// Transform
    Transform(CompressionTransform),
    /// NoCompression
    NoCompression(CompressionAbsent),
}

impl SlotChange {
    fn output_size(&self) -> u8 {
        match self {
            SlotChange::Add(op) => op.size,
            SlotChange::AddInlined(_) => 0,
            SlotChange::Sub(op) => op.size,
            SlotChange::Transform(op) => op.size,
            SlotChange::NoCompression(_) => 32,
        }
    }
    fn compressed(&self) -> &[u8] {
        let (bytes, size) = match self {
            SlotChange::Add(op) => (op.diff.as_le_slice(), op.size),
            SlotChange::AddInlined(_) => return &[], // data stored in metadata
            SlotChange::Sub(op) => (op.diff.as_le_slice(), op.size),
            SlotChange::Transform(op) => (op.diff.as_le_slice(), op.size),
            SlotChange::NoCompression(no) => (no.diff.as_le_slice(), 32),
        };
        &bytes[..size as usize]
    }

    /// Combine two changes into one which gives the same affect.
    pub fn combine(&self, right: &Self) -> Self {
        match (self, right) {
            (_left, right @ Self::Transform(_)) => *right,
            (_left, right @ Self::NoCompression(_)) => *right,

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

impl BorshSerialize for SlotChange {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        /// Generates the metadata byte for a given compression strategy.
        /// The metadata byte is structured as:
        /// First 5 bits: length of the compressed value
        /// Last 3 bits: operation id corresponding to the given compression used.
        const fn metadata_byte(output_size: u8, operation_id: u8) -> u8 {
            (output_size << 3) | operation_id
        }

        let operation_id = match self {
            SlotChange::Add(_) => 1,
            SlotChange::Sub(_) => 2,
            SlotChange::Transform(_) => 3,
            SlotChange::NoCompression(_) => 0,
            SlotChange::AddInlined(op) => {
                // a special case when we put data into metadata byte
                let metadata = metadata_byte(op.diff, 4);
                return writer.write_all(&[metadata]);
            }
        };
        let metadata = metadata_byte(self.output_size(), operation_id);
        writer.write_all(&[metadata])?;
        writer.write_all(self.compressed())
    }
}

impl BorshDeserialize for SlotChange {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut m_buf = [0u8];
        reader.read_exact(&mut m_buf)?;
        let metadata = m_buf[0];
        let id = metadata & 7;
        let size = metadata >> 3;

        if id > 4 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "Unexpected type of operation",
            ));
        }

        // handle a special case for AddInlined
        if id == 4 {
            return Ok(SlotChange::AddInlined(CompressionAddInlined { diff: size }));
        }

        // handle a special case for NoCompression
        let size = if id == 0 { 32 } else { size };

        let mut d_buff = [0u8; 32];
        let bytes = &mut d_buff[..size as usize];
        reader.read_exact(bytes)?;

        let diff = U256::from_le_slice(bytes);

        let slot_change = match id {
            0 => SlotChange::NoCompression(CompressionAbsent { diff }),
            1 => SlotChange::Add(CompressionAdd { diff, size }),
            2 => SlotChange::Sub(CompressionSub { diff, size }),
            3 => SlotChange::Transform(CompressionTransform { diff, size }),
            _ => {
                unreachable!("Only Add,Sub,Transform,NoCompression");
            }
        };

        Ok(slot_change)
    }
}

// Find a strategy with the least bytes to write.
fn select_best_strategy(
    compressors: impl Iterator<Item = Option<SlotChange>>,
    default: SlotChange,
) -> SlotChange {
    compressors
        .into_iter()
        .flatten()
        .min_by_key(|comp| comp.output_size())
        .unwrap_or(default)
}

/// For a given previous value and new value, try each compression strategy selecting the most
/// efficient one.
pub fn compress_two_best_strategy(prev_value: U256, new_value: U256) -> SlotChange {
    let add = CompressionAdd::new(prev_value, new_value);
    let add_inlined = CompressionAddInlined::new(prev_value, new_value);
    let sub = CompressionSub::new(prev_value, new_value);
    let transform = CompressionTransform::new(new_value);
    let no_compression = CompressionAbsent::new(new_value);

    let compressors = [
        // transform.map(SlotChange::Transform),
        add.map(SlotChange::Add),
        add_inlined.map(SlotChange::AddInlined),
        sub.map(SlotChange::Sub),
        transform.map(SlotChange::Transform),
    ];

    select_best_strategy(
        compressors.into_iter(),
        SlotChange::NoCompression(no_compression),
    )
}

/// For a given one value, try each compression strategy selecting the most
/// efficient one.
pub fn compress_one_best_strategy(new_value: U256) -> SlotChange {
    let transform = CompressionTransform::new(new_value);
    let no_compression = CompressionAbsent::new(new_value);

    let compressors = [transform.map(SlotChange::Transform)];

    select_best_strategy(
        compressors.into_iter(),
        SlotChange::NoCompression(no_compression),
    )
}

/// All possible diffs of a slot of Option<B256>
#[derive(Debug, PartialEq, Eq)]
pub enum CodeHashChange {
    /// Same
    Same,
    /// Removed
    Removed,
    /// Set
    Set(B256),
}

impl BorshSerialize for CodeHashChange {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        match self {
            CodeHashChange::Same => writer.write_all(&[0]),
            CodeHashChange::Removed => writer.write_all(&[1]),
            CodeHashChange::Set(val) => {
                writer.write_all(&[2])?;
                writer.write_all(val.as_slice())
            }
        }
    }
}

impl BorshDeserialize for CodeHashChange {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut m_buf = [0u8];
        reader.read_exact(&mut m_buf)?;
        let kind = m_buf[0];

        match kind {
            0 => Ok(CodeHashChange::Same),
            1 => Ok(CodeHashChange::Removed),
            2 => {
                let mut d_buff = [0u8; 32];
                let bytes = &mut d_buff[..];
                reader.read_exact(bytes)?;
                let value = B256::from_slice(bytes);

                Ok(CodeHashChange::Set(value))
            }
            _ => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "Unexpected type of operation",
            )),
        }
    }
}

/// For a given previous value and new value, try each compression strategy selecting the most
/// efficient one.
pub fn compress_two_code_hash(prev_value: Option<B256>, new_value: Option<B256>) -> CodeHashChange {
    if prev_value == new_value {
        CodeHashChange::Same
    } else if let Some(value) = new_value {
        CodeHashChange::Set(value)
    } else {
        CodeHashChange::Removed
    }
}

/// For a given one value, try each compression strategy selecting the most
/// efficient one.
pub fn compress_one_code_hash(new_value: Option<B256>) -> CodeHashChange {
    if let Some(value) = new_value {
        CodeHashChange::Set(value)
    } else {
        CodeHashChange::Removed
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{b256, U256};

    use super::*;

    #[test]
    fn borsh_slot_change() {
        let cases = [
            SlotChange::Add(CompressionAdd {
                diff: U256::from(257),
                size: 2,
            }),
            SlotChange::AddInlined(CompressionAddInlined { diff: 31 }),
            SlotChange::Sub(CompressionSub {
                diff: U256::from(257),
                size: 2,
            }),
            SlotChange::Transform(CompressionTransform {
                diff: U256::from(123456),
                size: 3,
            }),
            SlotChange::Transform(CompressionTransform {
                diff: U256::from(0),
                size: 0,
            }),
            SlotChange::NoCompression(CompressionAbsent { diff: U256::MAX }),
        ];

        for slot_change in cases {
            let serialized = borsh::to_vec(&slot_change).unwrap();
            let deserialized: SlotChange = borsh::from_slice(&serialized).unwrap();
            assert_eq!(deserialized, slot_change);
        }
    }

    #[test]
    fn borsh_code_hash_change() {
        let cases = [
            CodeHashChange::Same,
            CodeHashChange::Removed,
            CodeHashChange::Set(b256!(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )),
        ];

        for code_hash_change in cases {
            let serialized = borsh::to_vec(&code_hash_change).unwrap();
            let deserialized: CodeHashChange = borsh::from_slice(&serialized).unwrap();
            assert_eq!(deserialized, code_hash_change);
        }
    }

    #[test]
    fn compress_one_slot() {
        // Transform
        assert_eq!(
            compress_one_best_strategy(U256::from(257)),
            SlotChange::Transform(CompressionTransform {
                diff: U256::from(257),
                size: 2
            })
        );
        // NoCompression
        assert_eq!(
            compress_one_best_strategy(U256::MAX),
            SlotChange::NoCompression(CompressionAbsent { diff: U256::MAX })
        );
    }

    #[test]
    fn compress_two_slot() {
        // AddInlined
        assert_eq!(
            compress_two_best_strategy(U256::from(3), U256::from(34)),
            SlotChange::AddInlined(CompressionAddInlined { diff: 31 })
        );
        // Add
        assert_eq!(
            compress_two_best_strategy(U256::from(255), U256::from(287)),
            SlotChange::Add(CompressionAdd {
                diff: U256::from(32),
                size: 1
            })
        );
        // Sub
        assert_eq!(
            compress_two_best_strategy(U256::from(297), U256::from(265)),
            SlotChange::Sub(CompressionSub {
                diff: U256::from(32),
                size: 1
            })
        );
        // Sub overflow
        assert_eq!(
            compress_two_best_strategy(U256::from(2), U256::MAX - U256::from(2)),
            SlotChange::Sub(CompressionSub {
                diff: U256::from(5),
                size: 1
            })
        );
        // Transform
        assert_eq!(
            compress_two_best_strategy(U256::from(297), U256::ZERO),
            SlotChange::Transform(CompressionTransform {
                diff: U256::ZERO,
                size: 0
            })
        );
        // NoCompression
        assert_eq!(
            compress_two_best_strategy(
                U256::from_limbs([2, 2, 2, 2]),
                U256::from_limbs([u64::MAX / 2, u64::MAX / 2, u64::MAX / 2, u64::MAX / 2])
            ),
            SlotChange::NoCompression(CompressionAbsent {
                diff: U256::from_limbs([u64::MAX / 2, u64::MAX / 2, u64::MAX / 2, u64::MAX / 2]),
            })
        );
    }

    #[test]
    fn compress_two_code() {
        let a = b256!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b = b256!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        // Same
        assert_eq!(compress_two_code_hash(None, None), CodeHashChange::Same,);
        // Removed
        assert_eq!(
            compress_two_code_hash(Some(a), None),
            CodeHashChange::Removed,
        );
        // Set
        assert_eq!(
            compress_two_code_hash(Some(a), Some(b)),
            CodeHashChange::Set(b),
        );
        // Set
        assert_eq!(
            compress_two_code_hash(None, Some(b)),
            CodeHashChange::Set(b),
        );
    }

    // calc final change of a given slot value:
    // - a1 a2 a3 a4...
    // - change12 change23 change34...
    // return change12.combine(change23).combine(change34)...
    fn calc_final_change(slot_values: &[U256]) -> SlotChange {
        let changes: Vec<_> = slot_values
            .windows(2)
            .map(|s| {
                let [x, y] = s else {
                    panic!("size must be exactly 2 elems")
                };
                compress_two_best_strategy(*x, *y)
            })
            .collect();
        let final_change = changes.iter().fold(
            SlotChange::AddInlined(CompressionAddInlined { diff: 0 }),
            |init, elem| init.combine(elem),
        );
        final_change
    }

    fn apply_final_change(val: U256, change: SlotChange) -> U256 {
        match change {
            SlotChange::Add(op) => val.overflowing_add(op.diff).0,
            SlotChange::AddInlined(op) => val.overflowing_add(U256::from(op.diff)).0,
            SlotChange::Sub(op) => val.overflowing_sub(op.diff).0,
            SlotChange::NoCompression(op) => op.diff,
            SlotChange::Transform(op) => op.diff,
        }
    }

    #[test]
    fn compress_combination_1() {
        let nums = vec![
            U256::from(0),
            U256::from(1),
            U256::from(5),
            U256::from(35),
            U256::from(34),
        ];
        let final_change = calc_final_change(&nums);

        let first = *nums.first().unwrap();
        let last = *nums.last().unwrap();

        assert_eq!(last, apply_final_change(first, final_change));
    }

    #[test]
    fn compress_combination_2() {
        let nums = vec![
            U256::from_limbs([u64::MAX / 2, u64::MAX / 2, u64::MAX / 2, u64::MAX / 2]),
            U256::from(135),
        ];
        let final_change = calc_final_change(&nums);

        let first = *nums.first().unwrap();
        let last = *nums.last().unwrap();

        assert_eq!(last, apply_final_change(first, final_change));
    }
}
