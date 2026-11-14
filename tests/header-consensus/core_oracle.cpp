// Fixture/FFI only: arithmetic, target, difficulty and MTP decisions call the
// unmodified Bitcoin Core v29.0 implementation compiled by build.rs.
#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <string_view>

// Core's Assert failure handler; the full node's logging stack is not linked.
void assertion_fail(std::string_view, int, std::string_view, std::string_view) { std::abort(); }

static void big_endian(const arith_uint256& value, unsigned char* out) {
    const auto bytes = ArithToUint256(value);
    std::reverse_copy(bytes.begin(), bytes.end(), out);
}
static arith_uint256 from_big_endian(const unsigned char* bytes) {
    uint256 value;
    std::reverse_copy(bytes, bytes + 32, value.begin());
    return UintToArith256(value);
}
static Consensus::Params params(unsigned network) {
    Consensus::Params p{};
    unsigned bits = network == 2 ? 0x1e0377ae : network == 3 ? 0x207fffff : 0x1d00ffff;
    p.powLimit = ArithToUint256(arith_uint256{}.SetCompact(bits));
    p.nPowTargetSpacing = network == 2 ? 10 : 600;
    p.nPowTargetTimespan = p.nPowTargetSpacing * 2016;
    p.fPowAllowMinDifficultyBlocks = network == 1 || network == 3;
    p.fPowNoRetargeting = network == 3;
    p.enforce_BIP94 = network == 1;
    return p;
}

extern "C" void core_decode(unsigned bits, unsigned char* target, unsigned char* work) {
    bool negative, overflow;
    auto value = arith_uint256{}.SetCompact(bits, &negative, &overflow);
    big_endian(negative || overflow ? arith_uint256{} : value, target);
    CBlockIndex block;
    block.nBits = bits;
    big_endian(GetBlockProof(block), work);
}
extern "C" unsigned core_encode(const unsigned char* target) {
    return from_big_endian(target).GetCompact();
}
extern "C" bool core_pow(const unsigned char* hash_le, unsigned bits, unsigned network) {
    uint256 hash;
    std::copy_n(hash_le, 32, hash.begin());
    return CheckProofOfWorkImpl(hash, bits, params(network));
}

struct Epoch {
    std::array<CBlockIndex, 2016> blocks;
    Epoch() {
        for (int i = 0; i < 2016; ++i) {
            blocks[i].nHeight = i;
            if (i) blocks[i].pprev = &blocks[i - 1];
            blocks[i].BuildSkip();
        }
    }
};
extern "C" unsigned core_retarget(unsigned bits, unsigned first, unsigned last, unsigned network) {
    thread_local Epoch epoch;
    epoch.blocks[0].nBits = bits;
    epoch.blocks[0].nTime = first;
    epoch.blocks[2015].nBits = bits;
    epoch.blocks[2015].nTime = last;
    return CalculateNextWorkRequired(&epoch.blocks[2015], first, params(network));
}
extern "C" unsigned core_next_bits(unsigned base_bits, unsigned last_bits, unsigned last_time,
                                   unsigned next_time, unsigned height, unsigned network) {
    // This oracle covers non-retarget steps, including returning from a
    // minimum-difficulty exception to the last non-exception target.
    CBlockIndex previous, tip;
    previous.nHeight = height - 2;
    previous.nBits = base_bits;
    tip.nHeight = height - 1;
    tip.nBits = last_bits;
    tip.nTime = last_time;
    tip.pprev = &previous;
    CBlockHeader next;
    next.nTime = next_time;
    return GetNextWorkRequired(&tip, &next, params(network));
}
extern "C" long long core_median(const unsigned* times, unsigned count) {
    std::array<CBlockIndex, 11> blocks;
    for (unsigned i = 0; i < count; ++i) {
        blocks[i].nTime = times[i];
        if (i) blocks[i].pprev = &blocks[i - 1];
    }
    return blocks[count - 1].GetMedianTimePast();
}
