//! Native differential tests, not zkVM execution or complete contextual validation.
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/production.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{CompactTarget, Target};
    use crypto_bigint::{Encoding, U256};
    use proptest::prelude::*;

    unsafe extern "C" {
        fn core_decode(bits: u32, target: *mut u8, work: *mut u8);
        fn core_encode(target: *const u8) -> u32;
        fn core_pow(hash: *const u8, bits: u32, network: u32) -> bool;
        fn core_retarget(bits: u32, first: u32, last: u32, network: u32) -> u32;
        fn core_median(times: *const u32, count: u32) -> i64;
    }

    fn core_target_work(bits: u32) -> ([u8; 32], [u8; 32]) {
        let (mut target, mut work) = ([0; 32], [0; 32]);
        // Fixed-size buffers; the oracle does not retain pointers.
        unsafe { core_decode(bits, target.as_mut_ptr(), work.as_mut_ptr()) };
        (target, work)
    }

    fn retarget(bits: u32, first: u32, last: u32, network: u32) {
        let max_bits = if network == 2 { 0x1e0377ae } else { 0x1d00ffff };
        let max = core_target_work(max_bits).0;
        let period = if network == 2 { 20160 } else { 1209600 };
        let expected = unsafe { core_retarget(bits, first, last, network) };
        let citrea = citrea_0::target_to_bits(&citrea_0::calculate_new_difficulty(
            first,
            last,
            bits,
            U256::from_be_bytes(max),
            period,
        ));
        let clementine = match network {
            0 => clementine_0::calculate_new_difficulty(first, last, bits),
            1 => clementine_1::calculate_new_difficulty(first, last, bits),
            2 => clementine_2::calculate_new_difficulty(first, last, bits),
            _ => unreachable!(),
        };
        assert_eq!(
            citrea, expected,
            "Citrea retarget: bits={bits:x} first={first} last={last}"
        );
        assert_eq!(
            clementine_0::target_to_bits(&clementine),
            expected,
            "Clementine retarget: bits={bits:x} first={first} last={last}"
        );
        let mut params = bitcoin::consensus::Params::MAINNET;
        params.pow_target_timespan = u64::from(period);
        params.max_attainable_target = Target::from_be_bytes(max);
        // This API takes unsigned elapsed time. Normalize negative elapsed time
        // to zero explicitly; do NOT use its unsigned header subtraction helper.
        let elapsed = (i64::from(last) - i64::from(first)).max(0) as u64;
        assert_eq!(
            CompactTarget::from_next_work_required(
                CompactTarget::from_consensus(bits),
                elapsed,
                params
            )
            .to_consensus(),
            expected
        );
    }

    #[test]
    fn reversed_epoch_regression() {
        for network in 0..3 {
            retarget(0x1c123456, 2_000_000, 1_000_000, network);
            retarget(0x1c123456, u32::MAX, 0, network);
        }
    }

    #[test]
    fn small_and_invalid_target_regressions() {
        for bits in [
            0, 0x01010000, 0x02008000, 0x03008000, 0x01810000, 0x1d80ffff, 0x21010000, 0x22000100,
            0x23000001, 0xff123456,
        ] {
            let (target, work) = core_target_work(bits);
            assert_eq!(citrea_0::bits_to_target(bits), target);
            assert_eq!(clementine_0::bits_to_target(bits), target);
            assert_eq!(citrea_0::target_to_work(&target).to_be_bytes(), work);
            assert_eq!(clementine_0::calculate_work(&target).to_be_bytes(), work);
            let compact = unsafe { core_encode(target.as_ptr()) };
            assert_eq!(citrea_0::target_to_bits(&target), compact);
            assert_eq!(clementine_0::target_to_bits(&target), compact);
        }
    }

    #[test]
    fn early_mtp_regression() {
        let mut times = [0; 11];
        times[0] = 100;
        let core = unsafe { core_median(times.as_ptr(), 1) };
        assert_eq!(
            clementine_0::validate_header_timestamp(100, times, 1),
            100 > core
        );
    }

    #[test]
    fn rust_bitcoin_is_not_an_identical_oracle() {
        for bits in [0, 0x01010000, 0x01810000] {
            let (target, work) = core_target_work(bits);
            let rust = Target::from_compact(CompactTarget::from_consensus(bits));
            assert_ne!(rust.to_work().to_be_bytes(), work);
            if bits == 0x01810000 {
                assert_ne!(rust.to_be_bytes(), target);
            }
        }
        // Expose the header helper's reverse-time bug too. In debug it panics;
        // in release its wrapping subtraction selects the maximum clamp.
        use bitcoin::{
            block::{Header, Version},
            hashes::Hash,
            BlockHash, TxMerkleNode,
        };
        let first = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2_000_000,
            bits: CompactTarget::from_consensus(0x1c123456),
            nonce: 0,
        };
        let last = Header {
            time: 1_000_000,
            ..first
        };
        let result = std::panic::catch_unwind(|| {
            CompactTarget::from_header_difficulty_adjustment(
                first,
                last,
                bitcoin::consensus::Params::MAINNET,
            )
        });
        if let Ok(bits) = result {
            assert_ne!(bits.to_consensus(), unsafe {
                core_retarget(0x1c123456, first.time, last.time, 0)
            });
        }
    }

    #[test]
    fn retarget_clamp_boundaries() {
        for network in 0..3 {
            let period = if network == 2 { 20160 } else { 1209600 };
            for elapsed in [
                0,
                period / 4 - 1,
                period / 4,
                period / 4 + 1,
                period * 4 - 1,
                period * 4,
                period * 4 + 1,
                u32::MAX,
            ] {
                retarget(0x1c123456, 0, elapsed, network);
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_compact(bits in any::<u32>()) {
            let (target, work) = core_target_work(bits);
            prop_assert_eq!(citrea_0::bits_to_target(bits), target);
            prop_assert_eq!(clementine_0::bits_to_target(bits), target);
            prop_assert_eq!(citrea_0::target_to_work(&target).to_be_bytes(), work);
            prop_assert_eq!(clementine_0::calculate_work(&target).to_be_bytes(), work);
            // rust-bitcoin exposes no negative/overflow flag; compare valid positives only.
            if bits & 0x00800000 == 0 && target != [0;32] {
                prop_assert_eq!(Target::from_compact(CompactTarget::from_consensus(bits)).to_be_bytes(), target);
            }
        }

        #[test]
        fn arbitrary_target(raw in any::<[u8;32]>()) {
            let core = unsafe { core_encode(raw.as_ptr()) };
            prop_assert_eq!(citrea_0::target_to_bits(&raw), core);
            prop_assert_eq!(clementine_0::target_to_bits(&raw), core);
            let rust = Target::from_be_bytes(raw);
            prop_assert_eq!(rust.to_compact_lossy().to_consensus(), core);
            if raw > U256::ONE.to_be_bytes() {
                prop_assert_eq!(citrea_0::target_to_work(&raw).to_be_bytes(), rust.to_work().to_be_bytes());
                prop_assert_eq!(clementine_0::calculate_work(&raw).to_be_bytes(), rust.to_work().to_be_bytes());
            }
        }

        #[test]
        fn arbitrary_retarget(mut raw in any::<[u8;32]>(), first in any::<u32>(), last in any::<u32>(), network in 0u32..3) {
            // Valid targets only, preserving headroom for Core's fixed-width multiply.
            raw[..4].fill(0);
            if raw == [0;32] { raw[31] = 1; }
            let max = core_target_work(if network == 2 {0x1e0377ae} else {0x1d00ffff}).0;
            raw = raw.min(max);
            let bits = unsafe {core_encode(raw.as_ptr())};
            retarget(bits, first, last, network);
        }

        #[test]
        fn median_boundaries(times in any::<[u32;11]>(), count in 1u32..12) {
            let core = unsafe {core_median(times.as_ptr(), count)} as u32;
            prop_assert!(!clementine_0::validate_header_timestamp(core, times, count));
            if core < u32::MAX {
                prop_assert!(clementine_0::validate_header_timestamp(core+1, times, count));
            }
            if count == 11 {
                prop_assert!(!citrea_0::verify_timestamp(core, times));
                if core < u32::MAX { prop_assert!(citrea_0::verify_timestamp(core+1, times)); }
            }
        }

        #[test]
        fn proof_of_work(mut raw in any::<[u8;32]>(), hash in any::<[u8;32]>(), network in 0u32..4) {
            let max_bits = [0x1d00ffff,0x1d00ffff,0x1e0377ae,0x207fffff][network as usize];
            raw = raw.min(core_target_work(max_bits).0);
            if raw == [0;32] {raw[31]=1;}
            let bits = unsafe {core_encode(raw.as_ptr())};
            let target = core_target_work(bits).0;
            let expected = unsafe {core_pow(hash.as_ptr(),bits,network)};
            prop_assert_eq!(citrea_0::verify_target_hash(hash,target), expected);
            use bitcoin::hashes::Hash;
            prop_assert_eq!(Target::from_be_bytes(target).is_met_by(bitcoin::BlockHash::from_byte_array(hash)), expected);
            // The inclusive PoW boundary must be accepted by both production helpers.
            let mut boundary = target;
            boundary.reverse();
            prop_assert!(unsafe {core_pow(boundary.as_ptr(),bits,network)}, "Core accepts hash equal to target");
            prop_assert!(citrea_0::verify_target_hash(boundary,target));
            clementine_0::check_hash_valid(&boundary,&target);
        }

        #[test]
        fn testnet4_epoch_timewarp(last in any::<u32>(), distance in 599i64..602) {
            let mut times = [0;11];
            times[2015 % 11] = last;
            let time = (i64::from(last)-distance).clamp(0,i64::from(u32::MAX)) as u32;
            let mtp = unsafe {core_median(times.as_ptr(),11)};
            // Explicit BIP94 boundary assertion, not a call to Core ContextualCheckBlockHeader.
            let expected = i64::from(time)>mtp && i64::from(time)>=i64::from(last)-600;
            prop_assert_eq!(clementine_1::validate_header_timestamp(time,times,2016),expected);
            prop_assert_eq!(clementine_0::validate_header_timestamp(time,times,2016),i64::from(time)>mtp);
        }
    }
}
