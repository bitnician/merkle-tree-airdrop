//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.9;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title Airdrop
/// @author Bitnician
/// @notice A contract for airdropping ERC20 token which allows claimers to claim
/// their tokens using either signatures, or a Merkle proof. Once quantum computers
/// have broken ECDSA, an owner can turn off the ability to verify using ECDSA signatures
/// leaving only Merkle proof verification (which uses cryptographic hash functions resistant
/// to quantum computers).
contract Airdrop is Ownable {
    /// @notice Address of the ERC20 token
    IERC20 public immutable erc20Token;

    /// @notice A merkle proof used to prove inclusion in a set of airdrop recipient addresses.
    /// Claimers can provide a merkle proof using this merkle root and claim their airdropped
    /// tokens
    bytes32 public immutable merkleRoot;

    /// @notice The address whose private key will create all the signatures which claimers
    /// can use to claim their airdropped tokens
    address public immutable signer;

    /// @notice true if a claimer is able to call `Airdrop.signatureClaim` without reverting, false otherwise.
    /// False by default
    /// @dev We could call this `isECDSAEnabled`, but then we would waste gas first setting it to true, only
    /// later to set it to false. With the current variable name we only use a single SSTORE going from false -> true
    bool public isECDSADisabled;

    /// @notice A mapping to keep track of which addresses
    /// have already claimed their airdrop
    mapping(address => bool) public alreadyClaimed;

    /// @notice the EIP712 domain separator for claiming ERC20
    bytes32 public immutable EIP712_DOMAIN;

    /// @notice EIP-712 typehash for claiming ERC20
    bytes32 public constant CLAIM_TYPEHASH =
        keccak256("Claim(address claimer,uint256 amount)");

    /// @notice Sets the necessary initial claimer verification data
    constructor(
        bytes32 _root,
        address _signer,
        IERC20 _erc20Token
    ) {
        merkleRoot = _root;
        signer = _signer;
        erc20Token = _erc20Token;

        EIP712_DOMAIN = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("Airdrop")),
                keccak256(bytes("v1")),
                block.chainid,
                address(this)
            )
        );
    }

    modifier hasNotClaimed(address _claimer) {
        require(!alreadyClaimed[_claimer], "Already claimed");
        _;
    }

    modifier validSender(address _claimer) {
        require(msg.sender == _claimer, "Invalid Sender");
        _;
    }

    /// @notice Allows a msg.sender to claim their ERC20 token by providing a
    /// signature signed by the `Airdrop.signer` address.
    /// @dev An address can only claim its ERC20 once
    /// @dev See `Airdrop.toTypedDataHash` for how to format the pre-signed data
    /// @param signature An array of bytes representing a signature created by the
    /// `Airdrop.signer` address
    /// @param _to The address the claimed ERC20 should be sent to
    function signatureClaim(
        bytes calldata signature,
        address _to,
        uint256 _amount
    ) external hasNotClaimed(_to) validSender(_to) {
        require(!isECDSADisabled, "SIGS_DISABLED");

        bytes32 digest = toTypedDataHash(_to, _amount);
        address _signer = ECDSA.recover(digest, signature);

        require(_signer == signer, "INVALID_SIGNER");

        alreadyClaimed[_to] = true;

        require(erc20Token.transfer(_to, _amount), "TRANSFER_FAILED");
    }

    /// @notice Allows a msg.sender to claim their ERC20 token by providing a
    /// merkle proof proving their address is indeed committed to by the Merkle root
    /// stored in `Airdrop.merkleRoot`
    /// @dev An address can only claim its ERC20 once
    /// @dev See `Airdrop.toLeafFormat` for how to format the Merkle leaf data
    /// @param _proof An array of keccak hashes used to prove msg.sender's address
    /// is included in the Merkle tree represented by `Airdrop.merkleRoot`
    /// @param _to The address the claimed ERC20 should be sent to
    function merkleClaim(
        bytes32[] calldata _proof,
        bytes32 _leaf,
        address _to,
        uint256 _amount
    ) external hasNotClaimed(_to) validSender(_to) {
        require(keccak256(abi.encode(_to, _amount)) == _leaf, "INVALID_LEAF");
        bytes32 computedHash = _leaf;

        for (uint256 i = 0; i < _proof.length; i++) {
            bytes32 proofElement = _proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }

        require(computedHash == merkleRoot, "INVALID_MERKLE_ROOT");

        alreadyClaimed[_to] = true;

        require(erc20Token.transfer(_to, _amount), "TRANSFER_FAILED");
    }

    /// @notice Causes `Airdrop.signatureClaim` to always revert
    /// @notice Should be called when the owner learns offchain that quantum
    /// computers have advanced to the point of breaking ECDSA, and thus the
    /// `Airdrop.signatureClaim` function is insecure
    function disableECDSAVerification() external onlyOwner {
        isECDSADisabled = true;
        emit ECDSADisabled(msg.sender);
    }

    /// @dev Helper function for formatting the claimer data in an EIP-712 compatible way
    /// @param _recipient The address which will receive ERC20 from a successful claim
    /// @param _amount The amount of ERC20 to be claimed
    /// @return A 32-byte hash, which will have been signed by `Airdrop.signer`
    function toTypedDataHash(address _recipient, uint256 _amount)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(CLAIM_TYPEHASH, _recipient, _amount)
        );
        return ECDSA.toTypedDataHash(EIP712_DOMAIN, structHash);
    }

    /// @dev Helper function for formatting the claimer data stored in a Merkle tree leaf
    /// @param _recipient The address which will receive ERC20 from a successful claim
    /// @param _amount The amount of ERC20 to be claimed
    /// @return A 32-byte hash, which is one of the leaves of the Merkle tree represented by
    /// `Airdrop.merkleRoot`
    function toLeafFormat(address _recipient, uint256 _amount)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(bytes(abi.encode(_recipient, _amount)));
    }

    event ECDSADisabled(address owner);
}
