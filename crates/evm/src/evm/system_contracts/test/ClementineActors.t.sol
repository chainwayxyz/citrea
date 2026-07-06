// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../src/ClementineActors.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";

contract ClementineActorsHarness is ClementineActors {
    function recordGarbledSetup_(bytes32 operatorKey, bytes32 watchtowerKey) external {
        _recordGarbledSetup(operatorKey, watchtowerKey);
    }
}

contract FalseClementineActors is ClementineActors {
    function falseFunc() public pure returns (bytes32) {
        return keccak256("false");
    }
}

contract MockSchnorrPrecompileForActors {
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant NN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant U255_MAX_PLUS_1 =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    fallback(bytes calldata) external returns (bytes memory) {
        uint256 px;
        uint256 rx;
        uint256 s;
        bytes32 m;

        assembly {
            px := calldataload(0)
            m := calldataload(32)
            rx := calldataload(64)
            s := calldataload(96)
        }

        return abi.encode(verify(px, rx, s, m));
    }

    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) public pure returns (bytes memory) {
        if (px >= PP || rx >= PP || s >= NN) {
            return hex"";
        }

        (address exp_, bool ok) = convToFakeAddr(rx);
        if (!ok) {
            return hex"";
        }

        uint256 e = computeChallenge(bytes32(rx), bytes32(px), m);
        bytes32 sp = bytes32(NN - mulmod(s, px, NN));
        bytes32 ep = bytes32(NN - mulmod(e, px, NN));
        address rvh = ecrecover(sp, 27, bytes32(px), ep);

        assembly {
            if eq(rvh, exp_) {
                let result := mload(0x40)
                mstore(0x40, add(result, 0x20))
                mstore(result, 1)
                return(result, 0x20)
            }
            let result := mload(0x40)
            mstore(0x40, result)
            return(result, 0)
        }
    }

    function liftX(uint256 _x) internal pure returns (uint256, bool) {
        if (_x >= PP) {
            return (0, false);
        }

        uint256 y2 = addmod(mulmod(_x, mulmod(_x, _x, PP), PP), addmod(mulmod(_x, AA, PP), BB, PP), PP);
        y2 = expMod(y2, (PP + 1) / 4, PP);
        uint256 y = (y2 & 1) == 0 ? y2 : PP - y2;

        return (y, true);
    }

    function convToFakeAddr(uint256 px) internal pure returns (address, bool) {
        (uint256 py, bool ok) = liftX(px);
        if (!ok) {
            return (address(0), false);
        }
        bytes32 h = keccak256(abi.encodePacked(bytes32(px), bytes32(py)));
        return (address(uint160(uint256(h))), true);
    }

    function computeChallenge(bytes32 rx, bytes32 px, bytes32 m) internal pure returns (uint256) {
        bytes32 tag = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;
        return uint256(sha256(abi.encodePacked(tag, tag, rx, px, m))) % NN;
    }

    function expMod(uint256 _base, uint256 _exp, uint256 _pp) internal pure returns (uint256) {
        require(_pp != 0, "Modulus is zero");

        if (_base == 0) {
            return 0;
        }
        if (_exp == 0) {
            return 1;
        }

        uint256 r = 1;
        uint256 bit = U255_MAX_PLUS_1;
        assembly {
            for {} gt(bit, 0) {} {
                r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, bit)))), _pp)
                r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 2))))), _pp)
                r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 4))))), _pp)
                r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 8))))), _pp)
                bit := div(bit, 16)
            }
        }

        return r;
    }
}

contract MockSchnorrPrecompileAlwaysRejectForActors {
    fallback(bytes calldata) external returns (bytes memory) {
        return hex"";
    }
}

contract ClementineActorsTest is Test {
    ClementineActorsHarness public actors;

    address owner = makeAddr("citrea_owner");
    address operator = makeAddr("citrea_operator");
    address user = makeAddr("citrea_user");

    bytes32 operatorKey = hex"1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
    bytes32 watchtowerKey = hex"4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";
    bytes32 operatorKey2 = hex"2b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
    bytes32 watchtowerKey2 = hex"5d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";
    bytes32 securityCouncilKey = hex"8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b";
    bytes32 sourceShaScriptPubkeys = hex"4c7b976c44d0d2226d7c5288010306c0a773402a7007f6a05aac50a37076cfaa";

    ProxyAdmin proxyAdmin = ProxyAdmin(0x31fFFfFfFFFffFFFFFFfFFffffFFffffFfFFfffF);

    function setUp() public {
        proxyAdmin = new ProxyAdmin();
        proxyAdmin.transferOwnership(owner);

        address actorsImpl = address(new ClementineActorsHarness());

        bytes32[] memory council = new bytes32[](1);
        council[0] = securityCouncilKey;

        bytes memory initializeData =
            abi.encodeWithSelector(ClementineActors.initialize.selector, owner, operator, 1, 1, council);
        address proxyImpl = address(new TransparentUpgradeableProxy(actorsImpl, address(proxyAdmin), initializeData));
        actors = ClementineActorsHarness(proxyImpl);

        vm.etch(address(0x200), address(new MockSchnorrPrecompileForActors()).code);
    }

    function testInitializeSetsRolesAndCouncil() public view {
        assertEq(actors.operator(), operator);
        assertEq(actors.owner(), owner);
        assertEq(actors.circuitVersion(), 1);
        assertEq(actors.securityCouncilThreshold(), 1);
        assertTrue(actors.signingPaused());
        assertEq(actors.setupGeneration(), 1);

        bytes32[] memory council = actors.getSecurityCouncil();
        assertEq(council.length, 1);
        assertEq(council[0], securityCouncilKey);
    }

    function testCannotReinitialize() public {
        bytes32[] memory council = new bytes32[](1);
        council[0] = securityCouncilKey;

        vm.expectRevert("Contract is already initialized");
        actors.initialize(owner, operator, 1, 1, council);
    }

    function testOnlyOwnerCanSetOperator() public {
        vm.prank(user);
        vm.expectRevert();
        actors.setOperator(user);
    }

    function testCannotSetOperatorToZero() public {
        vm.prank(owner);
        vm.expectRevert("Operator cannot be zero address");
        actors.setOperator(address(0));
    }

    function testOnlyOperatorCanAddCandidates() public {
        bytes32[] memory operators = single(operatorKey);
        vm.prank(user);
        vm.expectRevert("caller is not the operator");
        actors.addCandidateOperators(operators);

        bytes32[] memory watchtowers = single(watchtowerKey);
        vm.prank(user);
        vm.expectRevert("caller is not the operator");
        actors.addCandidateWatchtowers(watchtowers);
    }

    function testOperatorCanAddCandidateActors() public {
        addCandidatePair(operatorKey, watchtowerKey);

        assertTrue(actors.isCandidateOperator(operatorKey));
        assertTrue(actors.isCandidateWatchtower(watchtowerKey));
        assertEq(actors.getCandidateOperators().length, 1);
        assertEq(actors.getCandidateWatchtowers().length, 1);
    }

    function testCannotAddDuplicateCandidateActors() public {
        addCandidatePair(operatorKey, watchtowerKey);

        vm.prank(operator);
        vm.expectRevert("Candidate operator already exists");
        actors.addCandidateOperators(single(operatorKey));

        vm.prank(operator);
        vm.expectRevert("Candidate watchtower already exists");
        actors.addCandidateWatchtowers(single(watchtowerKey));
    }

    function testProveGarbledSetupFromCircuitGeneratedTx() public {
        addCandidatePair(operatorKey, watchtowerKey);

        vm.expectEmit();
        emit ClementineActors.GarbledSetupProven(
            operatorKey,
            watchtowerKey,
            hex"bb7cf4dd1b97240deba895bbb7afdd86db8853d49e3dbd894c7e28e001b36e1c",
            hex"a2868aec3b441f5f651d05e5516b3e1d6ae97056fc1e514ff0f700521b339461",
            1
        );
        actors.proveGarbledSetup(
            circuitGeneratedTx(),
            operatorKey,
            watchtowerKey,
            990,
            sourceShaScriptPubkeys
        );
        assertTrue(actors.garbledSetups(operatorKey, watchtowerKey));
    }

    function testCannotProveSetupForNonCandidateOperator() public {
        vm.prank(operator);
        actors.addCandidateWatchtowers(single(watchtowerKey));

        vm.expectRevert("Operator is not candidate");
        actors.proveGarbledSetup(
            circuitGeneratedTx(),
            operatorKey,
            watchtowerKey,
            990,
            sourceShaScriptPubkeys
        );
    }

    function testCannotProveSetupForNonCandidateWatchtower() public {
        vm.prank(operator);
        actors.addCandidateOperators(single(operatorKey));

        vm.expectRevert("Watchtower is not candidate");
        actors.proveGarbledSetup(
            circuitGeneratedTx(),
            operatorKey,
            watchtowerKey,
            990,
            sourceShaScriptPubkeys
        );
    }

    function testCannotProveSetupWithWrongShaScriptPubkeys() public {
        addCandidatePair(operatorKey, watchtowerKey);

        vm.expectRevert("Invalid signature");
        actors.proveGarbledSetup(circuitGeneratedTx(), operatorKey, watchtowerKey, 990, bytes32(0));
    }

    function testCannotProveSetupWithWrongCircuitVersion() public {
        addCandidatePair(operatorKey, watchtowerKey);

        vm.prank(owner);
        actors.setCircuitVersion(2);

        vm.expectRevert("Invalid circuit version");
        actors.proveGarbledSetup(
            circuitGeneratedTx(),
            operatorKey,
            watchtowerKey,
            990,
            sourceShaScriptPubkeys
        );
    }

    function testCannotProveSetupWithInvalidSignature() public {
        addCandidatePair(operatorKey, watchtowerKey);
        vm.etch(address(0x200), address(new MockSchnorrPrecompileAlwaysRejectForActors()).code);

        vm.expectRevert("Invalid signature");
        actors.proveGarbledSetup(
            circuitGeneratedTx(),
            operatorKey,
            watchtowerKey,
            990,
            sourceShaScriptPubkeys
        );
    }

    function testCanSetInitialActiveActors() public {
        addCandidatePair(operatorKey, watchtowerKey);
        actors.recordGarbledSetup_(operatorKey, watchtowerKey);

        vm.prank(operator);
        actors.setActiveActors(single(operatorKey), single(watchtowerKey));

        assertFalse(actors.signingPaused());
        assertTrue(actors.isActiveOperator(operatorKey));
        assertTrue(actors.isActiveWatchtower(watchtowerKey));
        assertEq(actors.getActiveOperators().length, 1);
        assertEq(actors.getActiveWatchtowers().length, 1);
    }

    function testCannotSetInitialActiveActorsWithoutEverySetup() public {
        addCandidatePair(operatorKey, watchtowerKey);
        addCandidatePair(operatorKey2, watchtowerKey2);
        actors.recordGarbledSetup_(operatorKey, watchtowerKey);

        bytes32[] memory operators = new bytes32[](2);
        operators[0] = operatorKey;
        operators[1] = operatorKey2;

        vm.prank(operator);
        vm.expectRevert("Missing garbled setup");
        actors.setActiveActors(operators, single(watchtowerKey));
    }

    function testCannotSetInitialActiveActorsTwice() public {
        setActivePair();

        vm.prank(operator);
        vm.expectRevert("Active actors already set");
        actors.setActiveActors(single(operatorKey), single(watchtowerKey));
    }

    function testCanAddActiveOperatorWhenSetupWithAllWatchtowers() public {
        setActivePair();

        vm.prank(operator);
        actors.addCandidateOperators(single(operatorKey2));
        actors.recordGarbledSetup_(operatorKey2, watchtowerKey);

        vm.prank(operator);
        actors.addActiveOperators(single(operatorKey2));

        assertTrue(actors.isActiveOperator(operatorKey2));
        assertEq(actors.getActiveOperators().length, 2);
    }

    function testCannotAddActiveOperatorWithoutSetup() public {
        setActivePair();

        vm.prank(operator);
        actors.addCandidateOperators(single(operatorKey2));

        vm.prank(operator);
        vm.expectRevert("Missing garbled setup");
        actors.addActiveOperators(single(operatorKey2));
    }

    function testCanAddActiveWatchtowerWhenSetupWithAllOperators() public {
        setActivePair();

        vm.prank(operator);
        actors.addCandidateWatchtowers(single(watchtowerKey2));
        actors.recordGarbledSetup_(operatorKey, watchtowerKey2);

        vm.prank(operator);
        actors.addActiveWatchtowers(single(watchtowerKey2));

        assertTrue(actors.isActiveWatchtower(watchtowerKey2));
        assertEq(actors.getActiveWatchtowers().length, 2);
    }

    function testCannotAddActiveWatchtowerWithoutSetup() public {
        setActivePair();

        vm.prank(operator);
        actors.addCandidateWatchtowers(single(watchtowerKey2));

        vm.prank(operator);
        vm.expectRevert("Missing garbled setup");
        actors.addActiveWatchtowers(single(watchtowerKey2));
    }

    function testOwnerCanRemoveActiveOperator() public {
        setActivePair();

        vm.prank(owner);
        actors.removeActiveOperator(operatorKey);

        assertFalse(actors.isActiveOperator(operatorKey));
        assertEq(actors.getActiveOperators().length, 0);
    }

    function testOwnerCanRemoveActiveWatchtower() public {
        setActivePair();

        vm.prank(owner);
        actors.removeActiveWatchtower(watchtowerKey);

        assertFalse(actors.isActiveWatchtower(watchtowerKey));
        assertEq(actors.getActiveWatchtowers().length, 0);
    }

    function testNonOwnerCannotRemoveActiveActors() public {
        setActivePair();

        vm.prank(user);
        vm.expectRevert();
        actors.removeActiveOperator(operatorKey);

        vm.prank(user);
        vm.expectRevert();
        actors.removeActiveWatchtower(watchtowerKey);
    }

    function testCircuitVersionUpdatePausesAndClearsState() public {
        setActivePair();

        vm.prank(owner);
        actors.setCircuitVersion(2);

        assertEq(actors.circuitVersion(), 2);
        assertTrue(actors.signingPaused());
        assertEq(actors.getActiveOperators().length, 0);
        assertEq(actors.getActiveWatchtowers().length, 0);
        assertFalse(actors.garbledSetups(operatorKey, watchtowerKey));
        assertTrue(actors.isCandidateOperator(operatorKey));
        assertTrue(actors.isCandidateWatchtower(watchtowerKey));
    }

    function testSecurityCouncilUpdatePausesAndClearsState() public {
        setActivePair();
        bytes32[] memory council = new bytes32[](2);
        council[0] = securityCouncilKey;
        council[1] = hex"7f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b";

        vm.prank(owner);
        actors.setSecurityCouncil(2, council);

        assertEq(actors.securityCouncilThreshold(), 2);
        assertEq(actors.getSecurityCouncil().length, 2);
        assertTrue(actors.signingPaused());
        assertEq(actors.getActiveOperators().length, 0);
        assertEq(actors.getActiveWatchtowers().length, 0);
        assertFalse(actors.garbledSetups(operatorKey, watchtowerKey));
    }

    function testOwnerOrOperatorCanSetSigningPause() public {
        vm.prank(operator);
        actors.setSigningPause(false);
        assertFalse(actors.signingPaused());

        vm.prank(owner);
        actors.setSigningPause(true);
        assertTrue(actors.signingPaused());
    }

    function testUserCannotSetSigningPause() public {
        vm.prank(user);
        vm.expectRevert("caller is not the owner or operator");
        actors.setSigningPause(false);
    }

    function testUpgrade() public {
        address falseImpl = address(new FalseClementineActors());
        vm.prank(owner);
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(payable(address(actors))), falseImpl);
        assertEq(FalseClementineActors(address(actors)).falseFunc(), keccak256("false"));
    }

    function addCandidatePair(bytes32 _operatorKey, bytes32 _watchtowerKey) internal {
        vm.startPrank(operator);
        if (!actors.isCandidateOperator(_operatorKey)) {
            actors.addCandidateOperators(single(_operatorKey));
        }
        if (!actors.isCandidateWatchtower(_watchtowerKey)) {
            actors.addCandidateWatchtowers(single(_watchtowerKey));
        }
        vm.stopPrank();
    }

    function setActivePair() internal {
        addCandidatePair(operatorKey, watchtowerKey);
        actors.recordGarbledSetup_(operatorKey, watchtowerKey);

        vm.prank(operator);
        actors.setActiveActors(single(operatorKey), single(watchtowerKey));
    }

    function single(bytes32 value) internal pure returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = value;
    }

    function circuitGeneratedTx() internal pure returns (ClementineActors.Transaction memory) {
        return ClementineActors.Transaction(
            hex"03000000",
            hex"0001",
            hex"0100000000000000000000000000000000000000000000000000000000000000000000000000fdffffff",
            hex"02de030000000000002251205f02a2138b617c13ec6964fed95327f488af3ecab0c356fca67e08a2294af8c400000000000000000451024e73",
            hex"044061ec92580312bb1cf2970fcc8d727423b7d9d199e97d3d1e43637f920742c1da354c18efe709ed28b3ae5ce2840bf2e7290cb72632fd6fc49017afe643555cff40ee25d32a92f2fdc75391d463d85b87949178ec5d9ad81d46c7eada9b3ce28b6833ac46d9391d64d78278d1a68cb2f6bd92b216c9daa667b0a0016bc7cb9a2dd170204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ad201b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fad510063020100240000000000000000000000000000000000000000000000000000000000000000ffffffff6821c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            hex"00000000"
        );
    }
}
