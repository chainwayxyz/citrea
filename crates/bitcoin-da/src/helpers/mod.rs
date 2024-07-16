// Tags that are used to seperate the different parts of the script
const ROLLUP_NAME_TAG: &[u8; 1] = &[1; 1];
const SIGNATURE_TAG: &[u8; 1] = &[2; 1];
const PUBLICKEY_TAG: &[u8; 1] = &[3; 1];
const RANDOM_TAG: &[u8; 1] = &[4; 1];
const BODY_TAG: &[u8; 0] = &[];

#[cfg(feature = "native")]
pub mod builders;
pub mod compression;
pub mod parsers;
#[cfg(test)]
pub mod test_utils;
