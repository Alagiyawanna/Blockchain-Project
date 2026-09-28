// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ThreatRegistry
 * @author ThreatChain Team
 * @notice Decentralized Cyber Threat Intelligence Registry
 * @dev Stores Indicators of Compromise (IoCs) on an immutable blockchain ledger.
 *      Only authorized SOC analysts (ANALYST_ROLE) can register threats, preventing
 *      hash-poisoning and Sybil attacks. All records are tamper-proof and auditable.
 */
contract ThreatRegistry is AccessControl {
    // ─── Roles ───────────────────────────────────────────────────────────
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");

    // ─── Data Structures ─────────────────────────────────────────────────
    struct ThreatIoC {
        bytes32 malwareHash;      // SHA-256 hash of the malicious file / artifact
        string  threatType;       // e.g., "Ransomware", "Trojan", "C2_IP", "Worm"
        uint8   severity;         // 1 = Low, 2 = Medium, 3 = High, 4 = Critical, 5 = Emergency
        address reporter;         // Ethereum address of the SOC analyst who reported it
        uint256 timestamp;        // Block timestamp when the IoC was registered
        string  description;      // CVE ID, malware family name, or analyst notes
        bool    isActive;         // True = active threat; False = revoked / false positive
    }

    // ─── State Variables ─────────────────────────────────────────────────
    /// @dev O(1) lookup: hash → IoC record
    mapping(bytes32 => ThreatIoC) private threatDatabase;

    /// @dev Array of all registered hashes (for enumeration / frontend listing)
    bytes32[] public allThreatHashes;

    /// @dev Total count of registered threats
    uint256 public threatCount;

    // ─── Events ──────────────────────────────────────────────────────────
    event ThreatReported(
        bytes32 indexed malwareHash,
        string  threatType,
        uint8   severity,
        address indexed reporter,
        uint256 timestamp,
        string  description
    );

    event ThreatRevoked(
        bytes32 indexed malwareHash,
        address indexed revokedBy,
        string  reason,
        uint256 timestamp
    );

    event AnalystAdded(address indexed analyst, address indexed addedBy);
    event AnalystRemoved(address indexed analyst, address indexed removedBy);

    // ─── Errors ──────────────────────────────────────────────────────────
    error ThreatAlreadyExists(bytes32 malwareHash);
    error ThreatNotFound(bytes32 malwareHash);
    error InvalidSeverity(uint8 severity);
    error EmptyHash();

    // ─── Constructor ─────────────────────────────────────────────────────
    /**
     * @notice Deploys the registry and grants the deployer DEFAULT_ADMIN_ROLE
     *         and ANALYST_ROLE so they can immediately register threats and
     *         onboard other analysts.
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANALYST_ROLE, msg.sender);
    }

    // ─── Analyst Management ──────────────────────────────────────────────
    /**
     * @notice Admin adds a new SOC analyst who can register threats.
     * @param _analyst Ethereum address of the analyst to authorize.
     */
    function addAnalyst(address _analyst) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(ANALYST_ROLE, _analyst);
        emit AnalystAdded(_analyst, msg.sender);
    }

    /**
     * @notice Admin removes an SOC analyst's reporting privileges.
     * @param _analyst Ethereum address of the analyst to remove.
     */
    function removeAnalyst(address _analyst) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(ANALYST_ROLE, _analyst);
        emit AnalystRemoved(_analyst, msg.sender);
    }

    // ─── Core Functions ──────────────────────────────────────────────────
    /**
     * @notice Register a new Indicator of Compromise on the immutable ledger.
     * @param _hash       SHA-256 hash of the malicious file (as bytes32).
     * @param _threatType Classification string (e.g., "Ransomware").
     * @param _severity   Severity level 1–5.
     * @param _description Analyst notes, CVE ID, or malware family name.
     */
    function registerThreat(
        bytes32 _hash,
        string calldata _threatType,
        uint8 _severity,
        string calldata _description
    ) external onlyRole(ANALYST_ROLE) {
        if (_hash == bytes32(0)) revert EmptyHash();
        if (_severity < 1 || _severity > 5) revert InvalidSeverity(_severity);
        if (threatDatabase[_hash].malwareHash != bytes32(0)) revert ThreatAlreadyExists(_hash);

        ThreatIoC memory newThreat = ThreatIoC({
            malwareHash: _hash,
            threatType: _threatType,
            severity: _severity,
            reporter: msg.sender,
            timestamp: block.timestamp,
            description: _description,
            isActive: true
        });

        threatDatabase[_hash] = newThreat;
        allThreatHashes.push(_hash);
        threatCount++;

        emit ThreatReported(
            _hash,
            _threatType,
            _severity,
            msg.sender,
            block.timestamp,
            _description
        );
    }

    /**
     * @notice Check if a hash is a known active threat. Used by the Python edge agent.
     * @param _hash The SHA-256 file hash to check.
     * @return exists  Whether the hash is in the registry.
     * @return severity The threat severity (0 if not found).
     * @return threatType The classification string (empty if not found).
     */
    function isThreat(bytes32 _hash)
        external
        view
        returns (bool exists, uint8 severity, string memory threatType)
    {
        ThreatIoC storage threat = threatDatabase[_hash];
        if (threat.malwareHash != bytes32(0) && threat.isActive) {
            return (true, threat.severity, threat.threatType);
        }
        return (false, 0, "");
    }

    /**
     * @notice Retrieve full details of a registered threat.
     * @param _hash The SHA-256 hash to look up.
     * @return The complete ThreatIoC struct.
     */
    function getThreatDetails(bytes32 _hash) external view returns (ThreatIoC memory) {
        if (threatDatabase[_hash].malwareHash == bytes32(0)) revert ThreatNotFound(_hash);
        return threatDatabase[_hash];
    }

    /**
     * @notice Revoke a previously registered threat (e.g., false positive).
     *         The record remains on-chain for audit, but isActive is set to false.
     * @param _hash   The hash to revoke.
     * @param _reason Explanation for the revocation.
     */
    function revokeThreat(bytes32 _hash, string calldata _reason)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (threatDatabase[_hash].malwareHash == bytes32(0)) revert ThreatNotFound(_hash);

        threatDatabase[_hash].isActive = false;

        emit ThreatRevoked(_hash, msg.sender, _reason, block.timestamp);
    }

    /**
     * @notice Get all registered threat hashes (for frontend enumeration).
     * @return Array of all bytes32 hashes ever registered.
     */
    function getAllThreats() external view returns (bytes32[] memory) {
        return allThreatHashes;
    }

    /**
     * @notice Get a paginated list of threat hashes.
     * @param _offset Starting index.
     * @param _limit  Maximum number of results.
     * @return hashes Array of bytes32 hashes in the requested range.
     */
    function getThreats(uint256 _offset, uint256 _limit)
        external
        view
        returns (bytes32[] memory hashes)
    {
        uint256 end = _offset + _limit;
        if (end > allThreatHashes.length) {
            end = allThreatHashes.length;
        }

        uint256 length = end - _offset;
        hashes = new bytes32[](length);

        for (uint256 i = 0; i < length; i++) {
            hashes[i] = allThreatHashes[_offset + i];
        }
    }
}
