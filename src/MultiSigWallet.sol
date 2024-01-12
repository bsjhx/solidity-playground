// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title MultiSigWallet
 * @author Michal Rakoczy
 * @dev A contract for managing multi-signature wallets using Foundry and addressing a signature replay exploit with nonces.
 * @dev Owners can deposit any amount without requiring signatures. To withdraw, a signed transaction is needed.
 * @notice This implementation supports two owners by default, but it can be extended for more owners by adjusting the constructor.
 * @notice Each owner can deposit any amount without needing signatures.
 * @notice To withdraw Ether, a signed transaction is required.
 */
contract MultiSigWallet {
    using ECDSA for bytes32;

    address[2] public s_owners; // Array to store wallet owners
    mapping(bytes32 => bool) private s_executed; // Mapping to track executed transactions

    /**
     * @param _owners Array of addresses representing the owners required to manage the wallet.
     */
    constructor(address[2] memory _owners) payable {
        s_owners = _owners;
    }

    /**
     * @dev Allows any owner to deposit Ether into the wallet.
     */
    function deposit() external payable {}

    /**
     * @notice Transfers `_amount` Eth from the wallet to `_to` using signed transactions in `_sigs`.
     * @notice This is part of a broken implementation that doesn't use nonce and is susceptible to a signature replay exploit.
     * @param _to The address to which the Ether is being transferred.
     * @param _amount The amount of Ether to be transferred.
     * @param _sigs Array of signatures from the wallet owners.
     */
    function transfer(address _to, uint256 _amount, bytes[2] memory _sigs) external {
        bytes32 txHash = getTxHash(_to, _amount);
        require(_checkSigs(_sigs, txHash), "Invalid signature");
        (bool sent,) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    /**
     * @notice Transfers `_amount` Eth from the wallet to `_to` using signed transactions in `_sigs` with a nonce.
     * @param _to The address to which the Ether is being transferred.
     * @param _amount The amount of Ether to be transferred.
     * @param _nonce Nonce to prevent signature replay attacks.
     * @param _sigs Array of signatures from the wallet owners.
     */
    function transferOk(address _to, uint256 _amount, uint256 _nonce, bytes[2] memory _sigs) external {
        bytes32 txHash = getTxHashOk(_to, _amount, _nonce);
        require(!s_executed[txHash], "Signature already used");
        require(_checkSigs(_sigs, txHash), "Invalid signature");

        s_executed[txHash] = true;
        (bool sent,) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    /**
     * @notice Generates the transaction hash without a nonce.
     * @param _to The address to which the Ether is being transferred.
     * @param _amount The amount of Ether to be transferred.
     */
    function getTxHash(address _to, uint256 _amount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _amount));
    }

    /**
     * @notice Generates the transaction hash with a nonce to prevent signature replay attacks.
     * @param _to The address to which the Ether is being transferred.
     * @param _amount The amount of Ether to be transferred.
     * @param _nonce Nonce to prevent signature replay attacks.
     */
    function getTxHashOk(address _to, uint256 _amount, uint256 _nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _amount, _nonce));
    }

    /**
     * @dev Internal function to check the validity of multiple signatures.
     * @param _sigs Array of signatures from the wallet owners.
     * @param _txHash The hash of the transaction.
     * @return A boolean indicating whether all signatures are valid.
     */
    function _checkSigs(bytes[2] memory _sigs, bytes32 _txHash) private view returns (bool) {
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
