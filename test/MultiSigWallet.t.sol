// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Test.sol";
import "../src/MultiSigWallet.sol";
import "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

// https://book.getfoundry.sh/cheatcodes/sign
contract MultiSigWalletTest is Test {
    using ECDSA for bytes32;

    MultiSigWallet private wallet;
    address private evil = address(666);

    address private aliceAddress;
    uint256 private alicePrivateKey;
    address private bobAddress;
    uint256 private bobPrivateKey;

    function setUp() public {
        (aliceAddress, alicePrivateKey) = makeAddrAndKey("alice");
        (bobAddress, bobPrivateKey) = makeAddrAndKey("bob");

        wallet = new MultiSigWallet([aliceAddress, bobAddress]);
        vm.deal(aliceAddress, 100 ether);
        vm.deal(bobAddress, 100 ether);
    }

    function test_signatureRepayExploit() public depositedEth {
        assertEq(address(wallet).balance, 20 ether);
        assertEq(evil.balance, 0 ether);

        // 1. Get tx hash
        vm.prank(aliceAddress);
        bytes32 txHash = wallet.getTxHash(evil, 1 ether);

        // 2. Alice signs tx hash
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(txHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);
        bytes memory aliceSignedTxHash = abi.encodePacked(r, s, v);

        // 2. Bob signs tx hash
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bobPrivateKey, digest);
        bytes memory bobSignedTxHash = abi.encodePacked(r2, s2, v2);

        // 3. Evil withdraw Eth
        vm.startPrank(evil);
        wallet.transfer(evil, 1 ether, [aliceSignedTxHash, bobSignedTxHash]);

        // 4. ... and does it again with same signed message
        wallet.transfer(evil, 1 ether, [aliceSignedTxHash, bobSignedTxHash]);

        vm.stopPrank();

        assertEq(address(wallet).balance, 18 ether);
        assertEq(evil.balance, 2 ether);
    }

    function test_signatureRepayExploitDoesNotOccur() public depositedEth {
        assertEq(address(wallet).balance, 20 ether);
        assertEq(evil.balance, 0 ether);

        // 1. Get tx hash
        vm.prank(aliceAddress);
        uint256 nonce = 0;
        bytes32 txHash = wallet.getTxHashOk(evil, 1 ether, nonce);

        // 2. Alice signs tx hash
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(txHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);
        bytes memory aliceSignedTxHash = abi.encodePacked(r, s, v);

        // 2. Bob signs tx hash
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(bobPrivateKey, digest);
        bytes memory bobSignedTxHash = abi.encodePacked(r2, s2, v2);

        // 3. Evil withdraw Eth
        vm.startPrank(evil);
        wallet.transferOk(evil, 1 ether, nonce, [aliceSignedTxHash, bobSignedTxHash]);

        // 4. ... and does it again with same signed message - transaction is reverted!
        vm.expectRevert(bytes("signature already used"));
        wallet.transferOk(evil, 1 ether, nonce, [aliceSignedTxHash, bobSignedTxHash]);

        vm.stopPrank();

        assertEq(address(wallet).balance, 19 ether);
        assertEq(evil.balance, 1 ether);
    }

    modifier depositedEth() {
        vm.prank(aliceAddress);
        wallet.deposit{value: 10 ether}();

        vm.prank(bobAddress);
        wallet.deposit{value: 10 ether}();

        _;
    }
}
