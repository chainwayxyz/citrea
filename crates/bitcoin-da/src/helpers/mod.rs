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
    pub(crate) typ: TransactionType,
}

impl<'a> TransactionHeader<'a> {
    fn to_bytes(&self) -> Vec<u8> {
        let typ = match self.typ {
            TransactionType::Inscribed => 0u16.to_le_bytes(),
            TransactionType::Unknown(v) => v.get().to_le_bytes(),
        };
        let mut result = vec![];
        result.extend_from_slice(&typ);
        result.extend_from_slice(self.rollup_name);
        result
    }
    fn from_bytes<'b: 'a>(bytes: &'b [u8]) -> Option<TransactionHeader<'a>>
    where
        'a: 'b,
    {
        let (type_slice, rollup_name) = bytes.split_at(2);
        if type_slice.len() != 2 {
            return None;
        }
        let mut type_bytes = [0; 2];
        type_bytes.copy_from_slice(type_slice);
        let typ = match u16::from_le_bytes(type_bytes) {
            0 => TransactionType::Inscribed,
            n => TransactionType::Unknown(NonZeroU16::new(n).expect("Is not zero")),
        };
        Some(Self { rollup_name, typ })
    }
}

/// Type represents
#[repr(u16)]
enum TransactionType {
    /// This type of transaction includes full body (< 400kb)
    Inscribed = 0,
    Unknown(NonZeroU16),
}
