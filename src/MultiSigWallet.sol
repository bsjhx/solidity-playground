// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title MultiSigWalletTest
 * @author Michal Rakoczy
 * @dev A example contract to show how manage signing messages using Foundry
 * @dev Also it shows signature repay exploit (and how to fix it with nonce)
 * @notice This implementation assumes only two owners but nothing in the way to add more (mostly change requires constructor)
 * @notice Each owner can deposits any amount it wants - it doesn't require signatures
 * @notice To withdraw Eth, signed tx is required
 */
contract MultiSigWallet {
    using ECDSA for bytes32;

    address[2] public s_owners;
    mapping(bytes32 => bool) private s_executed;

    /**
     * @param _owners Owners required to manage wallet
     */
    constructor(address[2] memory _owners) payable {
        s_owners = _owners;
    }

    function deposit() external payable {}

    /**
     * @notice Transfers `_amount` Eth from wallet to `_to`, requires signed tx in _sigs.
     * @notice This is part of broken implementation - it doesn't use nonce!!!
     */
    function transfer(
        address _to,
        uint256 _amount,
        bytes[2] memory _sigs
    ) external {
        bytes32 txHash = getTxHash(_to, _amount);
        require(_checkSigs(_sigs, txHash), "invalid sig");
        (bool sent,) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    function transferOk(
        address _to,
        uint256 _amount,
        uint256 _nonce,
        bytes[2] memory _sigs
    ) external {
        bytes32 txHash = getTxHashOk(_to, _amount, _nonce);
        require(!s_executed[txHash], "signature already used");
        require(_checkSigs(_sigs, txHash), "invalid sig");

        s_executed[txHash] = true;
        (bool sent,) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    /**
     * @notice This is part of broken implementation - it doesn't use nonce!!!
     */
    function getTxHash(address _to, uint256 _amount)
    public
    pure
    returns (bytes32)
    {
        return keccak256(abi.encodePacked(_to, _amount));
    }

    function getTxHashOk(address _to, uint256 _amount, uint256 _nonce)
    public
    pure
    returns (bytes32)
    {
        return keccak256(abi.encodePacked(_to, _amount, _nonce));
    }

    function _checkSigs(bytes[2] memory _sigs, bytes32 _txHash)
    private
    view
    returns (bool)
    {
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(_txHash);
        for (uint256 i = 0; i < _sigs.length; i++) {
            address signer = ethSignedHash.recover(_sigs[i]);
            bool valid = signer == s_owners[i];
            if (!valid) {
                return false;
            }
        }
        return true;
    }
}
