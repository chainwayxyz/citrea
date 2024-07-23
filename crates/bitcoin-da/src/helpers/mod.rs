use core::num::NonZeroU16;

#[cfg(feature = "native")]
pub mod builders;
pub mod compression;
pub mod parsers;
#[cfg(test)]
pub mod test_utils;

/// Header - first 8 bytes of any rollup transaction
struct TransactionHeader<'a> {
    pub(crate) rollup_name: &'a [u8],
    pub(crate) kind: TransactionKind,
}

impl<'a> TransactionHeader<'a> {
    fn to_bytes(&self) -> Vec<u8> {
        let kind = match self.kind {
            TransactionKind::Complete => 0u16.to_le_bytes(),
            TransactionKind::Unknown(v) => v.get().to_le_bytes(),
        };
        let mut result = vec![];
        result.extend_from_slice(&kind);
        result.extend_from_slice(self.rollup_name);
        result
    }
    fn from_bytes<'b: 'a>(bytes: &'b [u8]) -> Option<TransactionHeader<'a>>
    where
        'a: 'b,
    {
        let (kind_slice, rollup_name) = bytes.split_at(2);
        if kind_slice.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(kind_slice);
        let kind = match u16::from_le_bytes(kind_bytes) {
            0 => TransactionKind::Complete,
            n => TransactionKind::Unknown(NonZeroU16::new(n).expect("Is not zero")),
        };
        Some(Self { rollup_name, kind })
    }
}

/// Type represents
#[repr(u16)]
enum TransactionKind {
    /// This type of transaction includes full body (< 400kb)
    Complete = 0,
    Unknown(NonZeroU16),
}
