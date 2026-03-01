// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title EdgeClawDeviceRegistry
 * @notice On-chain device identity registry for EdgeClaw network (EVM).
 * @dev Stores Ed25519 public keys, device metadata, and active status.
 *      Only the device owner or contract admin can deactivate/reactivate.
 */
contract EdgeClawDeviceRegistry is Ownable {
    // ─── Structs ───────────────────────────────────────────

    struct DeviceRecord {
        string publicKey;     // Ed25519 public key (hex)
        string deviceName;
        string deviceType;
        address owner;
        uint256 registeredAt;
        bool active;
    }

    // ─── State ─────────────────────────────────────────────

    /// publicKey hash → DeviceRecord
    mapping(bytes32 => DeviceRecord) private _devices;

    /// Quick existence check
    mapping(bytes32 => bool) private _exists;

    /// Counter
    uint256 public deviceCount;

    // ─── Events ────────────────────────────────────────────

    event DeviceRegistered(
        bytes32 indexed keyHash,
        string publicKey,
        string deviceName,
        string deviceType,
        address indexed owner
    );

    event DeviceDeactivated(bytes32 indexed keyHash, address indexed by);
    event DeviceReactivated(bytes32 indexed keyHash, address indexed by);

    // ─── Errors ────────────────────────────────────────────

    error AlreadyRegistered(bytes32 keyHash);
    error DeviceNotFound(bytes32 keyHash);
    error NotAuthorized();

    // ─── Constructor ───────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ─── External Functions ────────────────────────────────

    /**
     * @notice Register a new device.
     * @param publicKey Ed25519 public key (hex string).
     * @param deviceName Human-readable device name.
     * @param deviceType Device type ("desktop", "mobile", "iot").
     */
    function registerDevice(
        string calldata publicKey,
        string calldata deviceName,
        string calldata deviceType
    ) external {
        bytes32 keyHash = keccak256(abi.encodePacked(publicKey));
        if (_exists[keyHash]) revert AlreadyRegistered(keyHash);

        _devices[keyHash] = DeviceRecord({
            publicKey: publicKey,
            deviceName: deviceName,
            deviceType: deviceType,
            owner: msg.sender,
            registeredAt: block.timestamp,
            active: true
        });
        _exists[keyHash] = true;
        deviceCount++;

        emit DeviceRegistered(keyHash, publicKey, deviceName, deviceType, msg.sender);
    }

    /**
     * @notice Deactivate a device. Only owner or admin.
     */
    function deactivateDevice(string calldata publicKey) external {
        bytes32 keyHash = keccak256(abi.encodePacked(publicKey));
        if (!_exists[keyHash]) revert DeviceNotFound(keyHash);

        DeviceRecord storage record = _devices[keyHash];
        if (msg.sender != record.owner && msg.sender != owner()) revert NotAuthorized();

        record.active = false;
        emit DeviceDeactivated(keyHash, msg.sender);
    }

    /**
     * @notice Reactivate a device. Only owner or admin.
     */
    function reactivateDevice(string calldata publicKey) external {
        bytes32 keyHash = keccak256(abi.encodePacked(publicKey));
        if (!_exists[keyHash]) revert DeviceNotFound(keyHash);

        DeviceRecord storage record = _devices[keyHash];
        if (msg.sender != record.owner && msg.sender != owner()) revert NotAuthorized();

        record.active = true;
        emit DeviceReactivated(keyHash, msg.sender);
    }

    // ─── View Functions ────────────────────────────────────

    function getDevice(string calldata publicKey) external view returns (DeviceRecord memory) {
        bytes32 keyHash = keccak256(abi.encodePacked(publicKey));
        if (!_exists[keyHash]) revert DeviceNotFound(keyHash);
        return _devices[keyHash];
    }

    function isRegistered(string calldata publicKey) external view returns (bool) {
        return _exists[keccak256(abi.encodePacked(publicKey))];
    }

    function isActive(string calldata publicKey) external view returns (bool) {
        bytes32 keyHash = keccak256(abi.encodePacked(publicKey));
        if (!_exists[keyHash]) return false;
        return _devices[keyHash].active;
    }
}
