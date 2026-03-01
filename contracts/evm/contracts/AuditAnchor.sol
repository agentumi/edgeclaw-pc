// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title EdgeClawAuditAnchor
 * @notice On-chain audit log anchoring for EdgeClaw network (EVM).
 * @dev Stores sequential audit batch hashes. Each anchor records a batch range
 *      and SHA-256 hash. The chain of anchors is verifiable for continuity.
 */
contract EdgeClawAuditAnchor is Ownable {
    // ─── Structs ───────────────────────────────────────────

    struct AnchorRecord {
        uint64 batchStart;
        uint64 batchEnd;
        bytes32 batchHash;     // SHA-256 hash of audit batch
        uint256 anchoredAt;    // Block timestamp
        address submitter;
    }

    // ─── State ─────────────────────────────────────────────

    AnchorRecord[] public anchors;
    uint64 public lastBatchEnd;

    // ─── Events ────────────────────────────────────────────

    event AuditAnchored(
        uint256 indexed anchorIndex,
        uint64 batchStart,
        uint64 batchEnd,
        bytes32 batchHash,
        address indexed submitter
    );

    // ─── Errors ────────────────────────────────────────────

    error InvalidRange(uint64 batchStart, uint64 batchEnd);
    error BatchOverlap(uint64 batchStart, uint64 lastEnd);

    // ─── Constructor ───────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ─── External Functions ────────────────────────────────

    /**
     * @notice Anchor a new audit batch hash on-chain.
     * @param batchStart Batch start index (inclusive).
     * @param batchEnd Batch end index (inclusive).
     * @param batchHash SHA-256 hash of the audit batch.
     */
    function anchorAudit(
        uint64 batchStart,
        uint64 batchEnd,
        bytes32 batchHash
    ) external onlyOwner {
        if (batchStart > batchEnd) revert InvalidRange(batchStart, batchEnd);
        if (anchors.length > 0 && batchStart <= lastBatchEnd)
            revert BatchOverlap(batchStart, lastBatchEnd);

        anchors.push(AnchorRecord({
            batchStart: batchStart,
            batchEnd: batchEnd,
            batchHash: batchHash,
            anchoredAt: block.timestamp,
            submitter: msg.sender
        }));

        lastBatchEnd = batchEnd;

        emit AuditAnchored(anchors.length - 1, batchStart, batchEnd, batchHash, msg.sender);
    }

    // ─── View Functions ────────────────────────────────────

    /**
     * @notice Get total number of audit anchors.
     */
    function anchorCount() external view returns (uint256) {
        return anchors.length;
    }

    /**
     * @notice Get a specific anchor record.
     */
    function getAnchor(uint256 index) external view returns (AnchorRecord memory) {
        return anchors[index];
    }

    /**
     * @notice Verify the entire anchor chain is contiguous (no gaps/overlaps).
     */
    function verifyChain() external view returns (bool) {
        if (anchors.length <= 1) return true;

        for (uint256 i = 1; i < anchors.length; i++) {
            if (anchors[i].batchStart <= anchors[i - 1].batchEnd) {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice Get all anchors in range.
     */
    function getAnchorsInRange(uint256 from, uint256 to) external view returns (AnchorRecord[] memory) {
        require(to <= anchors.length && from < to, "Invalid range");
        AnchorRecord[] memory result = new AnchorRecord[](to - from);
        for (uint256 i = from; i < to; i++) {
            result[i - from] = anchors[i];
        }
        return result;
    }
}
