// Originally written in 2019 by Matter Labs. Lisence: MIT/APACHE.

use alloy_primitives::{B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug)]
pub struct CompressionAdd {
    pub diff: U256,
    pub size: usize,
}

impl CompressionAdd {
    fn new(prev_value: U256, new_value: U256) -> Option<Self> {
        let (diff, _overflowed) = new_value.overflowing_sub(prev_value);
        let size = diff.byte_len();

        if size <= 30 {
            Some(Self { diff, size })
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct CompressionSub {
    pub diff: U256,
    pub size: usize,
}

impl CompressionSub {
    fn new(prev_value: U256, new_value: U256) -> Option<Self> {
        let (diff, _overflowed) = prev_value.overflowing_sub(new_value);
        let size = diff.byte_len();

        if size <= 30 {
            Some(Self { diff, size })
        } else {
            None
        }
    }
}

/// Only try to remove leading zeroes.
#[derive(Debug)]
pub struct CompressionTransform {
    pub diff: U256,
    pub size: usize,
}

impl CompressionTransform {
    fn new(new_value: U256) -> Option<Self> {
        let diff = new_value;
        let size = diff.byte_len();

        if size <= 30 {
            Some(Self { diff, size })
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct CompressionAbsent {
    pub diff: U256,
    pub size: usize,
}

impl CompressionAbsent {
    fn new(new_value: U256) -> Self {
        let diff = new_value;
        let size = 32;

        Self { diff, size }
    }
}

#[derive(Debug)]
pub enum SlotChange {
    Add(CompressionAdd),
    Sub(CompressionSub),
    Transform(CompressionTransform),
    NoCompression(CompressionAbsent),
}

impl SlotChange {
    fn output_size(&self) -> usize {
        match self {
            SlotChange::Add(add) => add.size,
            SlotChange::Sub(sub) => sub.size,
            SlotChange::Transform(transform) => transform.size,
            SlotChange::NoCompression(no) => no.size,
        }
    }
    fn compressed(&self) -> &[u8] {
        let (bytes, size) = match self {
            SlotChange::Add(add) => (add.diff.as_le_slice(), add.size),
            SlotChange::Sub(sub) => (sub.diff.as_le_slice(), sub.size),
            SlotChange::Transform(transform) => (transform.diff.as_le_slice(), transform.size),
            SlotChange::NoCompression(no) => (no.diff.as_le_slice(), no.size),
        };
        &bytes[..size]
    }
}

/// Generates the metadata byte for a given compression strategy.
/// The metadata byte is structured as:
/// First 5 bits: length of the compressed value
/// Last 3 bits: operation id corresponding to the given compression used.
fn metadata_byte(output_size: usize, operation_id: usize) -> u8 {
    ((output_size << 3) | operation_id) as u8
}

impl BorshSerialize for SlotChange {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let operation_id = match self {
            SlotChange::Add(_) => 1,
            SlotChange::Sub(_) => 2,
            SlotChange::Transform(_) => 3,
            SlotChange::NoCompression(_) => 0,
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
        let size = (metadata >> 3) as usize;

        if !(id == 0 || id == 1 || id == 2 || id == 3) {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "Unexpected type of operation",
            ));
        }

        if size > 32 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "Unexpected size of operation",
            ));
        }

        let mut d_buff = [0u8; 32];
        let bytes = &mut d_buff[..size];
        reader.read_exact(bytes)?;

        let diff = U256::from_le_slice(bytes);

        let slot_change = match id {
            0 => SlotChange::NoCompression(CompressionAbsent { diff, size }),
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
    let sub = CompressionSub::new(prev_value, new_value);
    let transform = CompressionTransform::new(new_value);
    let no_compression = CompressionAbsent::new(new_value);

    let compressors = [
        transform.map(SlotChange::Transform),
        add.map(SlotChange::Add),
        sub.map(SlotChange::Sub),
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

#[derive(Debug)]
pub enum CodeHashChange {
    Same,
    Removed,
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

pub fn compress_two_code_hash(prev_value: Option<B256>, new_value: Option<B256>) -> CodeHashChange {
    if prev_value == new_value {
        CodeHashChange::Same
    } else if let Some(value) = new_value {
        CodeHashChange::Set(value)
    } else {
        CodeHashChange::Removed
    }
}

pub fn compress_one_code_hash(new_value: Option<B256>) -> CodeHashChange {
    if let Some(value) = new_value {
        CodeHashChange::Set(value)
    } else {
        CodeHashChange::Removed
    }
}

/*
fn main() {
    // let x = U256::MAX - U256::from(1);
    // let y = U256::from(0);
    // let y = U256::from_limbs([98989898989, 4594895849584, 34546456, 4556756756]);

    let x = U256::from(0);
    let y = U256::from(257);
    let z = compress_two_best_strategy(x, y);
    dbg!(x, y, &z);

    let serialized = borsh::to_vec(&z).unwrap();
    dbg!(&serialized, serialized.len());

    let deserialized: SlotChange = borsh::from_slice(&serialized).unwrap();
    dbg!(deserialized);

    // let b = U256::from(1);

    // dbg!(x - b);
    // dbg!(U256::MAX);
}
*/
