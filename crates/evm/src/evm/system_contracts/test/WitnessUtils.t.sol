// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import "../lib/WitnessUtils.sol";

contract WitnessUtilsTest is Test {
    bytes4 version = hex"01000000";
    bytes2 flag = hex"0001";
    bytes vin = hex"01438afdb24e414d54cc4a17a95f3d40be90d23dfeeb07a48e9e782178efddd8890100000000fdffffff";
    bytes vout = hex"020db9a60000000000160014b549d227c9edd758288112fe3573c1f85240166880a81201000000001976a914ae28f233464e6da03c052155119a413d13f3380188ac";
    bytes witness = hex"024730440220200254b765f25126334b8de16ee4badf57315c047243942340c16cffd9b11196022074a9476633f093f229456ad904a9d97e26c271fc4f01d0501dec008e4aae71c2012102c37a3c5b21a5991d3d7b1e203be195be07104a1a19e5c2ed82329a56b4312130";
    bytes w2 = hex"0740b500164ed14931558b6f101350bd896d8ef7b5215268aec6fa97624f97d4e921f954c362dacb706875ba86280798f4a141745d09444d8f6a62483046bc1e87624025b756b973a6f96a60fde1e745765ffb5d4bfafbd3380e0044dfb0c4c59bba973d0806942a718458696f2c09f7c1a4f672479d7b8f678dff07badf546ab3d2004045d7ea88c30d6da0f4c08c808b2b72c02833a0bc1f44d901954e671e531a33e2b5919ebad1655c3df651b22591777649e60aab07b8507112df2b3da1c3ec65fd401f83b69afc860240e486af437c09949f7a9ab7a795090d3ce8a88ef3a460de56c0ed3bca888cae22e31495e1bcd22148d5185cbf05302b1d910096d18414368f400b6e7417ca7a5f3fefd221087288abbef35aa93db502bc9b32b4ce48edb666c6ea36d6a1d5fc2a78aaab61f71355b7816f7fe15bb3355c56720f7eb27d6ca8a3c3203402ede68395331e2797e1d8fd2ba951386baab32d1440252c3214e0708fe479ad20c18c593480f4f55a3fd7617c9df6e3dabc80fca5927f66d20050c82a2012be7aad2089c310c07b3c3901562a3f000c4a477fcb5ebfd362de3d07a0bff927f2911301ad2067de68f8eb816c86396802b389dedec01703d79e9910e0c846f48920a3e33dd7ad2040f1506702e400b8d1aed2de05bf776e6d7602378ab0834a7d771039454af56ead5100631401010101010101010101010101010101010101016841c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51e8bbb8cb70da9374d24ddfec9bfd8d90b89563c2a55de80fbeba57c0a2de1bce";
    bytes4 locktime = hex"00000000";
    bytes32 wtxId = hex"ff63ed0cc02c85a7aef6510625b6897abe1b969293f5db2991804e23f2562df1";
    bytes wExample = hex"06096af9822fdb33bbfb940c6e6ea3d182c36de9c428de5606dbb8f257b63a10b66f7e408fcf8ed73ce3c3abf2aa28d809ef64e1bc35146424d00e072631fe3a08749c3380609e8fcd080582e984c1b5026351016404031f73220a964e3d835c33a0be6ca70206c9044dbc1b2c04b3411e2a";
    bytes badWitness1 = hex"06096af9822fdb33bbfb940c6e6ea3d182c36de9c428de5606dbb8f257b63a10b66f7e408fcf8ed73ce3c3abf2aa28d809ef64e1bc35146424d00e072631fe3a08749c3380609e8fcd080582e984c1b5026351016404031f73220a964e3d835c33a0be6ca70206c9044dbc1b2c04b3411e";
    bytes badWitness2 = hex"06096af9822fdb33bbfb940c6e6ea3d182c36de9c428de5606dbb8f257b63a10b66f7e408fcf8ed73ce3c3abf2aa28d809ef64e1bc35146424d00e072631fe3a08749c3380609e8fcd080582e984c1b5026351016404031f73220a964e3d835c33a0be6ca70206c9044dbc1b2c04b3411e2a32";
    bytes badWitness3 = hex"06096af9822fdb33bbfb940c6e6ea3d182c36de9c428de5606dbb8f257b63a10b66f7e408fcf8ed73ce3c3abf2aa28d809ef64e1bc35146424d00e072631fe3a08749c3380609e8fcd080582e984c1b5026351016404031f73220a964e3d835c33a0be6ca70206c9044dbc1b2c04b3411e";
    bytes badArgWitness = hex"0101ff";
    bytes badArgWitness2 = hex"0101ff01ff";
    // Helper function to run Python script and get its output
    function getRandomWitness() public returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "python3";
        inputs[1] = "test/randomWitnessGenerator.py";
        
        bytes memory result = vm.ffi(inputs);
        return result;
    }

    function getRandomStackItem() public returns (bytes memory) {
        string[] memory inputs = new string[](2);
        inputs[0] = "python3";
        inputs[1] = "test/randomStackItemGenerator.py";
        
        bytes memory result = vm.ffi(inputs);
        return result;
    }

    function calculateWtxIdMock(
        bytes4 _version,
        bytes2 _flag,
        bytes calldata _vin,
        bytes calldata _vout,
        bytes calldata _witness,
        bytes4 _locktime
    ) public view returns(bytes32) {
        return WitnessUtils.calculateWtxId(
            _version, 
            _flag, 
            _vin, 
            _vout, 
            _witness, 
            _locktime
        );
    }

    function testCalculateWtxId() public view{
        bytes32 testWtxId = WitnessUtilsTest(address(this)).calculateWtxIdMock(
            version, 
            flag, 
            vin, 
            vout, 
            witness, 
            locktime
        );
        assertEq(testWtxId, wtxId);
    }

    function testValidateWitnessSpecific() public view {
        assert(WitnessUtils.validateWitness(wExample, 2));
    }

    function testDetermineWitnessLengthAt() public {
        uint256 _at;
        bytes memory randomWitness;
        for(int i = 0; i < 10; i++){
            bytes memory randomWits = getRandomWitness();
            randomWitness = abi.encodePacked(randomWitness, randomWits);            
            assertEq(randomWits.length, WitnessUtils.determineWitnessLengthAt(randomWitness, _at));
            _at += randomWits.length;
        }
    }

    function testDetermineWitnessLengthAtMiddle() public {
        bytes memory firstRandomWitness = getRandomWitness();
        bytes memory secondRandomWitness = getRandomWitness();
        bytes memory thirdRandomWitness = getRandomWitness();
        bytes memory fourthRandomWitness = getRandomWitness();

        bytes memory randomWitness = abi.encodePacked(firstRandomWitness, secondRandomWitness, thirdRandomWitness, fourthRandomWitness);

        assertEq(thirdRandomWitness.length, WitnessUtils.determineWitnessLengthAt(randomWitness, firstRandomWitness.length + secondRandomWitness.length));
    }
    
    // This is unusual because we are testing the determineWitnessLengthAt function to not work properly with a not proper witness. But we decided to keep it to increase the testing quality.
    function testDetermineWitnessLengthAtError() public view {
        assertNotEq(badWitness1.length, WitnessUtils.determineWitnessLengthAt(badWitness1, 0));
    }

    function testDetermineWitnessLengthAtError2() public view {
        assertEq(WitnessUtils.determineWitnessLengthAt(badArgWitness, 2), BTCUtils.ERR_BAD_ARG);
    }

    function testFuzzValidateWitness(uint8 x) public {
        vm.assume(x>0);
        vm.assume(x<4);
        bytes memory randomWitness;
        for (uint i = 0; i < x; i++){
            bytes memory randomWits = getRandomWitness();
            randomWitness = abi.encodePacked(randomWitness, randomWits);
        }
        assert(WitnessUtils.validateWitness(randomWitness, uint256(x)));
    }

    function testValidateWitnessError1() public view {
        assertFalse(WitnessUtils.validateWitness(badWitness1, 2));
    }
    function testValidateWitnessError2() public view {
        assertFalse(WitnessUtils.validateWitness(badWitness2, 2));
    }

    function testFuzzExtractWitnessAtIndex(uint8 x) public {
        vm.assume(x<10);

        bytes[] memory randomWitsArray = new bytes[](10);
        bytes memory randomWitness;

        for(uint i = 0; i < 10; i++){
            bytes memory randomWits = getRandomWitness();
            randomWitsArray[i] = randomWits;
            randomWitness = abi.encodePacked(randomWitness, randomWits);            
        }

        assertEq(randomWitsArray[x], WitnessUtils.extractWitnessAtIndex(randomWitness, x));
    }

    function testFuzzExtractItemFromWitness(uint8 x) public {
        vm.assume(x<9);

        bytes memory nStackItems = hex"09";
        bytes[] memory randomStackItemArray = new bytes[](9);
        bytes memory randomWits;
        randomWits = abi.encodePacked(nStackItems, randomWits);

        for(uint i = 0; i < 9; i++){
            bytes memory randomStackItem = getRandomStackItem();
            randomStackItemArray[i] = randomStackItem;
            randomWits = abi.encodePacked(randomWits, randomStackItem);            
        }

        assertEq(randomStackItemArray[x], WitnessUtils.extractItemFromWitness(randomWits, x));
    } 
}






