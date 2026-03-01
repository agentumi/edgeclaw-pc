// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title EdgeClawPolicyNFT
 * @notice RBAC policy tokens for the EdgeClaw network (EVM).
 * @dev Each NFT represents an RBAC policy with role, capabilities, expiry, and revocation status.
 *      Follows ERC-721 standard so policies are transferable and verifiable.
 */
contract EdgeClawPolicyNFT is ERC721Enumerable, Ownable {
    // ─── Structs ───────────────────────────────────────────

    struct Policy {
        string role;            // "owner","admin","operator","viewer","guest"
        string[] capabilities;  // Granted capability strings
        uint256 expiresAt;      // Unix timestamp (0 = never)
        address issuer;         // Who minted this policy
        uint256 createdAt;      // Mint timestamp
        bool revoked;           // Revocation flag
    }

    // ─── State ─────────────────────────────────────────────

    uint256 private _nextTokenId;

    /// tokenId → Policy
    mapping(uint256 => Policy) private _policies;

    /// Valid roles
    mapping(string => bool) private _validRoles;

    // ─── Events ────────────────────────────────────────────

    event PolicyMinted(uint256 indexed tokenId, address indexed owner, string role, address issuer);
    event PolicyRevoked(uint256 indexed tokenId, address indexed revokedBy);

    // ─── Errors ────────────────────────────────────────────

    error InvalidRole(string role);
    error PolicyAlreadyRevoked(uint256 tokenId);
    error NotIssuerOrAdmin(uint256 tokenId);
    error PolicyExpiredOrRevoked(uint256 tokenId);

    // ─── Constructor ───────────────────────────────────────

    constructor() ERC721("EdgeClaw Policy", "ECPOL") Ownable(msg.sender) {
        _validRoles["owner"] = true;
        _validRoles["admin"] = true;
        _validRoles["operator"] = true;
        _validRoles["viewer"] = true;
        _validRoles["guest"] = true;
    }

    // ─── External Functions ────────────────────────────────

    /**
     * @notice Mint a new Policy NFT.
     * @param to Policy recipient.
     * @param role Role string.
     * @param capabilities Array of capability strings.
     * @param expiresAt Expiry timestamp (0 = never).
     */
    function mintPolicy(
        address to,
        string calldata role,
        string[] calldata capabilities,
        uint256 expiresAt
    ) external onlyOwner returns (uint256) {
        if (!_validRoles[role]) revert InvalidRole(role);

        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);

        _policies[tokenId] = Policy({
            role: role,
            capabilities: capabilities,
            expiresAt: expiresAt,
            issuer: msg.sender,
            createdAt: block.timestamp,
            revoked: false
        });

        emit PolicyMinted(tokenId, to, role, msg.sender);
        return tokenId;
    }

    /**
     * @notice Revoke a policy. Only issuer or contract admin.
     */
    function revokePolicy(uint256 tokenId) external {
        Policy storage policy = _policies[tokenId];
        if (policy.revoked) revert PolicyAlreadyRevoked(tokenId);
        if (msg.sender != policy.issuer && msg.sender != owner()) revert NotIssuerOrAdmin(tokenId);

        policy.revoked = true;
        emit PolicyRevoked(tokenId, msg.sender);
    }

    // ─── View Functions ────────────────────────────────────

    /**
     * @notice Check if a policy is currently valid (not revoked, not expired).
     */
    function isPolicyValid(uint256 tokenId) external view returns (bool) {
        Policy storage policy = _policies[tokenId];
        if (policy.revoked) return false;
        if (policy.expiresAt > 0 && block.timestamp > policy.expiresAt) return false;
        return true;
    }

    function getPolicy(uint256 tokenId) external view returns (Policy memory) {
        return _policies[tokenId];
    }

    function isRevoked(uint256 tokenId) external view returns (bool) {
        return _policies[tokenId].revoked;
    }

    /**
     * @notice Get all valid policy IDs held by an address.
     */
    function validPoliciesOf(address holder) external view returns (uint256[] memory) {
        uint256 balance = balanceOf(holder);
        uint256[] memory temp = new uint256[](balance);
        uint256 count = 0;

        for (uint256 i = 0; i < balance; i++) {
            uint256 tokenId = tokenOfOwnerByIndex(holder, i);
            Policy storage policy = _policies[tokenId];
            if (!policy.revoked && (policy.expiresAt == 0 || block.timestamp <= policy.expiresAt)) {
                temp[count++] = tokenId;
            }
        }

        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = temp[i];
        }
        return result;
    }
}
