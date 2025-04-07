//! Serialization and deserialization -related logic.

use sov_modules_core::{StateCodec, StateKeyCodec, StateValueCodec};

mod bcs_codec;
mod borsh_codec;
mod rlp_codec;

pub use bcs_codec::BcsCodec;
pub use borsh_codec::BorshCodec;
pub use rlp_codec::RlpCodec;

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::strategy::Strategy;
    use sov_modules_core::EncodeKeyLike;

    use super::*;

    impl StateValueCodec<Vec<i32>> for BorshCodec {
        type Error = std::io::Error;

        fn encode_value(&self, value: &Vec<i32>) -> Vec<u8> {
            borsh::to_vec(value).unwrap()
        }

        fn try_decode_value(&self, bytes: &[u8]) -> Result<Vec<i32>, Self::Error> {
            borsh::from_slice(bytes)
        }
    }

    fn arb_vec_i32() -> impl Strategy<Value = Vec<i32>> {
        vec(any::<i32>(), 0..2048)
    }

    proptest::proptest! {
        #[test]
        fn test_borsh_slice_encode_alike(vec in arb_vec_i32()) {
            #[allow(non_local_definitions)]
            impl EncodeKeyLike<[i32], Vec<i32>> for BorshCodec
            {
                fn encode_key_like(&self, borrowed: &[i32]) -> Vec<u8> {
                    borsh::to_vec(&borrowed).unwrap()
                }
            }
            let codec = BorshCodec;
            assert_eq!(
                <BorshCodec as EncodeKeyLike<[i32], Vec<i32>>>::encode_key_like(&codec, &vec[..]),
                codec.encode_value(&vec)
            );
        }
    }
}
