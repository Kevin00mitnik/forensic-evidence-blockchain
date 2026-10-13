// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EvidenceCustody {
    struct Evidence {
        bytes32 fileHash;
        string filename;
        address registeredBy;
        uint64 registeredAt;
    }

    struct CustodyEntry {
        address actor;
        string action;
        uint64 recordedAt;
    }

    uint256 private evidenceCount;
    mapping(uint256 => Evidence) private evidenceById;
    mapping(uint256 => CustodyEntry[]) private custodyByEvidence;

    event EvidenceRegistered(
        uint256 indexed evidenceId,
        bytes32 indexed fileHash,
        string filename,
        address indexed registeredBy,
        uint64 registeredAt
    );
    event CustodyRecorded(
        uint256 indexed evidenceId,
        address indexed actor,
        string action,
        uint64 recordedAt
    );

    function registerEvidence(
        bytes32 fileHash,
        string calldata filename
    ) external returns (uint256 evidenceId) {
        require(fileHash != bytes32(0), "Evidence hash is required");
        require(bytes(filename).length > 0 && bytes(filename).length <= 255, "Invalid filename");

        evidenceId = ++evidenceCount;
        uint64 recordedAt = uint64(block.timestamp);
        evidenceById[evidenceId] = Evidence({
            fileHash: fileHash,
            filename: filename,
            registeredBy: msg.sender,
            registeredAt: recordedAt
        });
        custodyByEvidence[evidenceId].push(
            CustodyEntry(msg.sender, "REGISTERED", recordedAt)
        );

        emit EvidenceRegistered(
            evidenceId,
            fileHash,
            filename,
            msg.sender,
            recordedAt
        );
        emit CustodyRecorded(evidenceId, msg.sender, "REGISTERED", recordedAt);
    }

    function recordCustody(uint256 evidenceId, string calldata action) external {
        require(evidenceId > 0 && evidenceId <= evidenceCount, "Unknown evidence");
        require(bytes(action).length > 0 && bytes(action).length <= 64, "Invalid action");

        uint64 recordedAt = uint64(block.timestamp);
        custodyByEvidence[evidenceId].push(
            CustodyEntry(msg.sender, action, recordedAt)
        );
        emit CustodyRecorded(evidenceId, msg.sender, action, recordedAt);
    }

    function getEvidenceCount() external view returns (uint256) {
        return evidenceCount;
    }

    function getEvidence(
        uint256 evidenceId
    )
        external
        view
        returns (bytes32 fileHash, string memory filename, address registeredBy, uint64 registeredAt)
    {
        require(evidenceId > 0 && evidenceId <= evidenceCount, "Unknown evidence");
        Evidence storage item = evidenceById[evidenceId];
        return (item.fileHash, item.filename, item.registeredBy, item.registeredAt);
    }

    function getCustodyCount(uint256 evidenceId) external view returns (uint256) {
        require(evidenceId > 0 && evidenceId <= evidenceCount, "Unknown evidence");
        return custodyByEvidence[evidenceId].length;
    }

    function getCustodyEntry(
        uint256 evidenceId,
        uint256 entryIndex
    ) external view returns (address actor, string memory action, uint64 recordedAt) {
        require(evidenceId > 0 && evidenceId <= evidenceCount, "Unknown evidence");
        require(entryIndex < custodyByEvidence[evidenceId].length, "Unknown custody entry");
        CustodyEntry storage entry = custodyByEvidence[evidenceId][entryIndex];
        return (entry.actor, entry.action, entry.recordedAt);
    }
}
