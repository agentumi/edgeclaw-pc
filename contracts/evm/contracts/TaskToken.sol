// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title EdgeClawTaskToken (ECLAW)
 * @notice ERC-20 utility token for EdgeClaw task execution accounting.
 * @dev Supports minting (admin-only), burning, and task reward distribution.
 *      Total supply is uncapped; minted as task rewards are earned.
 */
contract EdgeClawTaskToken is ERC20, ERC20Burnable, Ownable {
    // ─── Events ────────────────────────────────────────────

    event TaskReward(bytes32 indexed taskId, uint256 amount, address indexed executor);
    event TokensMinted(uint256 amount, address indexed recipient);

    // ─── Constructor ───────────────────────────────────────

    constructor() ERC20("EdgeClaw Task Token", "ECLAW") Ownable(msg.sender) {}

    // ─── External Functions ────────────────────────────────

    /**
     * @notice Mint ECLAW tokens to a recipient. Admin only.
     * @param to Recipient address.
     * @param amount Token amount (18 decimals).
     */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
        emit TokensMinted(amount, to);
    }

    /**
     * @notice Reward a task executor with ECLAW tokens.
     * @param taskId Unique task identifier.
     * @param amount Reward amount.
     * @param executor Task executor address.
     */
    function rewardTask(bytes32 taskId, uint256 amount, address executor) external onlyOwner {
        _mint(executor, amount);
        emit TaskReward(taskId, amount, executor);
    }

    /**
     * @notice Batch reward multiple task executors.
     * @param taskIds Array of task identifiers.
     * @param amounts Array of reward amounts.
     * @param executors Array of executor addresses.
     */
    function batchReward(
        bytes32[] calldata taskIds,
        uint256[] calldata amounts,
        address[] calldata executors
    ) external onlyOwner {
        require(
            taskIds.length == amounts.length && amounts.length == executors.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < taskIds.length; i++) {
            _mint(executors[i], amounts[i]);
            emit TaskReward(taskIds[i], amounts[i], executors[i]);
        }
    }
}
