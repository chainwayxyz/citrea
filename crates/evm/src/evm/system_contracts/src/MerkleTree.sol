// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract MerkleTree {
    bytes32 public constant ZERO_VALUE = 0xcb0c9f4264546b15be9801ecb11df7e43bfc6841609fc1e4e9de5b3a5973af38; // keccak256("CITREA")

    uint32 public levels;
    mapping(uint256 => bytes32) filledSubtrees;
    bytes32 root;
    uint32 nextIndex;

    function initializeTree(uint32 _levels) internal {
        levels = _levels;
        for (uint32 i = 0; i < levels; i++) {
            filledSubtrees[i] = zeros(i);
        }
        root = zeros(levels);
    }

    function hashLeftRight(bytes32 _left, bytes32 _right) public pure returns (bytes32 value) {
        return sha256(abi.encodePacked(_left, _right));
    }

    function _insert(bytes32 _leaf) internal returns (uint32 index) {
        uint32 _nextIndex = nextIndex;
        require(_nextIndex != uint32(2) ** levels, "Merkle tree is full. No more leaves can be added");
        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = _leaf;
        bytes32 left;
        bytes32 right;

        for (uint32 i = 0; i < levels; i++) {
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = zeros(i);
                filledSubtrees[i] = currentLevelHash;
            } else {
                left = filledSubtrees[i];
                right = currentLevelHash;
            }
            currentLevelHash = hashLeftRight(left, right);
            currentIndex /= 2;
        }

        root = currentLevelHash;
        nextIndex = _nextIndex + 1;
        return _nextIndex;
    }

    // Insert function
    function insertWithdrawalTree(bytes32 _leaf) public returns (uint32 index) {
        return _insert(_leaf);
    }

    // Get root function
    function getRootWithdrawalTree() public view returns (bytes32) {
        return root;
    }

    /// @dev provides Zero (Empty) elements for a MiMC MerkleTree. Up to 32 levels
    function zeros(uint256 i) public pure returns (bytes32) {
        if (i == 0) {
            return bytes32(0xcb0c9f4264546b15be9801ecb11df7e43bfc6841609fc1e4e9de5b3a5973af38);
        } else if (i == 1) {
            return bytes32(0x455b22fd2c80e024797f8d83d31a0b6b11aa024ecffb905b1d691d657434b90a);
        } else if (i == 2) {
            return bytes32(0x480c45bfe41828a16e4bf0bd7a1db34d2ec4d239101daf0b774821ed2dfca761);
        } else if (i == 3) {
            return bytes32(0x29f2f8c3c9d792bd9ebdc71486151113b73af357a205dd41760f941555e26146);
        } else if (i == 4) {
            return bytes32(0xd0fb88bcc6243bb6021b49d377e1655d1e61fb08a659b9511680f83824d64197);
        } else if (i == 5) {
            return bytes32(0x5c7fac0890e73fb2e0d8fb3063c6786a2c63da95187efe29da4bce99d621d0ba);
        } else if (i == 6) {
            return bytes32(0xcb08837032cc923c34faece314b3e13158b7fda962321262618d4bcc46217eb2);
        } else if (i == 7) {
            return bytes32(0x229c0a76b756fc3db3266dc0f8e571d113ca44e0cb7326bee03d35331748091f);
        } else if (i == 8) {
            return bytes32(0x8270abf4c13bfeb13ee8967544be4d343424fa3910ec7ad995873ca0d86daf69);
        } else if (i == 9) {
            return bytes32(0x2d338a30d2a6bb5169df7cc8d61b6578d35568f6e1f09eda43f5bd36ad68be67);
        } else if (i == 10) {
            return bytes32(0x6609db0b330090c86c349ad31f986c5f2a346461eb6f160a0e0a865d39260df6);
        } else if (i == 11) {
            return bytes32(0x81861227312c9b868eb34b8cf216893c0db60b6b5c5e05f549f3ab6811b9f3d6);
        } else if (i == 12) {
            return bytes32(0x1f7af2d9c7e25a85c9035abd0d8c2c7b993754a4af7250924bc55071770f75ef);
        } else if (i == 13) {
            return bytes32(0x45d98c88c1c60a5d35eabe7a4cf3b2ba3bee0d8a4617f7bf485a5bd93749d3f0);
        } else if (i == 14) {
            return bytes32(0x11b8807d04fe98c0bd60dec1890026baa1d83f51b37e365a45b5c87028aaf6c9);
        } else if (i == 15) {
            return bytes32(0x6a43477876ca14f6d714ab184a94b3a8d324e29085646fd2bc3663427c512332);
        } else if (i == 16) {
            return bytes32(0x2e2ca637ce5b8e8b33629f637c7fd77c7ac300ae409e64898d38b4c177280e43);
        } else if (i == 17) {
            return bytes32(0x212db654d1d3a4e31fd8b86d3545babbf23ce592753c50936b30b1eb34d6db2a);
        } else if (i == 18) {
            return bytes32(0x7818b4041e25a0bcd1bf0528728f20c6976f0923d5038facff21524ccd971d75);
        } else if (i == 19) {
            return bytes32(0x538977a76a1b4557dd0e98d557d9a24d88349d83220ed84feb13c79f8ae83c7c);
        } else if (i == 20) {
            return bytes32(0x9f3efb03c31cf43571e1e5395e2f71fcaabc491ca72631b44ec9cf99110821be);
        } else if (i == 21) {
            return bytes32(0xfb29f69c3f45b34a9e0b7a4007a953190aa2618deef63b15ea4dd10998785734);
        } else if (i == 22) {
            return bytes32(0x3d12f73b1f682ed24aa0b1a39df347240a74a64b5e15312466368dd943e769bc);
        } else if (i == 23) {
            return bytes32(0x5bce4a357cef84ee3edf0669ec908843281b2d19072f58eff8d6503468b0c8d6);
        } else if (i == 24) {
            return bytes32(0x069835ff0850f45ad28f01399d6af695a96d056589cc0ac9259e66beae87cd3c);
        } else if (i == 25) {
            return bytes32(0xdbdece04a4bafc538705847f0c28d441f57c7b6dbf8a803ca0e5b097857e0513);
        } else if (i == 26) {
            return bytes32(0x020d43e87ea83e8ad54ca1eb11d826a2cd75823b5f6a91a6568839b42551f727);
        } else if (i == 27) {
            return bytes32(0x19a652f1c22915bd595b81d87a7dd5cc01ba7d82ba78882949373b6220d3a504);
        } else if (i == 28) {
            return bytes32(0x4138c0097adba86ca3c19d2181a21b8e331c42c1fdb3ce8cfd953a4553279ef1);
        } else if (i == 29) {
            return bytes32(0xfdc8ebd533132c3178ab8434060ae1007fc3b672fcf270d30b57f8e12ca7fa27);
        } else if (i == 30) {
            return bytes32(0xf0b266c6a0adb776bf7b9fafe1f02c99f35ba89067bcedb8f8f267002d51bceb);
        } else if (i == 31) {
            return bytes32(0x2afd595f486a771bf9653b9333d78bf101fad1f5ddb0db960c5a1450200061db);
        } else if (i == 32) {
            return bytes32(0x35c59abafcc58285f02e048ba62334323f15a2d2ea0a033f8df2fbee3344902d);
        } else {
            revert("Index out of bounds");
        }
    }
}
