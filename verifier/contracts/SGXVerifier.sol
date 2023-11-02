// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {IAttestation} from "./interfaces/IAttestation.sol";

contract SGXVerifier {
    
    event RequestAttestation(bytes32 hash);
    event ProverApproved(address prover);
    event AddAttestor(address attestor);
    event VoteAttestationReport(address attestor, bytes32 hash);
    event CommitBatch(uint256 indexed batchIndex, bytes32 indexed batchHash);

    address public owner;
    mapping(address => bool) public attestors;
    mapping(bytes32 => Report) public reports;
    mapping(address => uint256) public attestedProvers; // prover's pubkey => attestedTime
    mapping(bytes32 => BatchInfo) public batches;

    uint256 public attestValiditySeconds = 600;
    bytes32 public currentStateRoot;
    bytes32 public currentWithdrawalRoot;

    IAttestation public immutable dcapAttestation;

    struct BatchInfo {
        bytes32 newStateRoot;
        bytes32 prevStateRoot;
        bytes32 withdrawalRoot;
    }

    struct Report {
        uint approved;
        address prover;
        uint blockNumber;
        mapping(address => uint) votes; // 0: unvoted, 1: approve, 2: reject
    }

    uint256 public threshold = 1; // This is an example threshold. Adjust this value as needed.

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }
    
    modifier onlyAttestor() {
        require(attestors[msg.sender], "Not an attestor");
        _;
    }
    
    constructor(address attestationAddr) {
        owner = msg.sender;
        dcapAttestation = IAttestation(attestationAddr);
    }
    
    function changeOwner(address _newOwner) public onlyOwner {
        owner = _newOwner;
    }

    function changeAttestValiditySeconds(uint256 val) public onlyOwner {
        attestValiditySeconds = val;
    }
    
    function addAttestors(address[] memory _attestors) public onlyOwner {
        for (uint256 i = 0; i < _attestors.length; i++) {
            emit AddAttestor(_attestors[i]);
            attestors[_attestors[i]] = true;
        }
    }
    
    function removeAttestors(address[] memory _attestors) public onlyOwner {
        for (uint256 i = 0; i < _attestors.length; i++) {
            attestors[_attestors[i]] = false;
        }
    }

    function getReportBlockNumber(bytes32 reportHash) view public returns (uint) {
        return reports[reportHash].blockNumber;
    }

    function getVote(bytes32 reportHash, address attestor) view public returns (uint) {
        return reports[reportHash].votes[attestor];
    }

    function getReportProver(bytes32 reportHash) view public returns (address) {
        return reports[reportHash].prover;
    }
    
    function submitAttestationReport(address prover, bytes calldata reportBytes) public {
        bytes32 reportHash = keccak256(reportBytes);
        address reportProver = reports[reportHash].prover;
        require(reportProver == address(0) || reportProver != prover, "should not submit same report");
        reports[reportHash].prover = prover;
        reports[reportHash].blockNumber = block.number;
        emit RequestAttestation(reportHash);
    }

    function challengeReport(address attestor, bytes calldata reportBytes) public {
        bytes32 reportHash = keccak256(reportBytes);
        uint vote = reports[reportHash].votes[attestor];
        require(vote != 0, "invalid votes");
        bool approve = verifyAttestation(reportBytes);
        require((vote == 1 && !approve) || (vote == 2 && approve), "invalid challenge");

        uint approvedNum = reports[reportHash].approved;
        if (approve) {
            approvedNum += 1;
            reports[reportHash].votes[attestor] = 1;
        } else {
            approvedNum -= 1;
            reports[reportHash].votes[attestor] = 2;
        }
        reports[reportHash].approved = approvedNum;

        // update the attestedProvers list
        if (approvedNum < threshold) {
            attestedProvers[reports[reportHash].prover] = 0;
        } else {
            attestedProvers[reports[reportHash].prover] = 1;
        }

        // remove the attestor
        attestors[attestor] = false;
    }
    
    function voteAttestationReport(bytes32 reportHash, bool approve) public onlyAttestor {
        require(reports[reportHash].votes[msg.sender] == 0, "Attestor has already voted for this report.");
        uint approved = reports[reportHash].approved;
        
        if (approve) {
            reports[reportHash].votes[msg.sender] = 1;
            approved++;
            reports[reportHash].approved = approved;
        } else {
            reports[reportHash].votes[msg.sender] = 2;
        }
        
        if (approved >= threshold) {
            address prover = reports[reportHash].prover;
            attestedProvers[prover] = block.timestamp;
            emit ProverApproved(prover);
        }
        emit VoteAttestationReport(msg.sender, reportHash);
    }

    function commitBatch(uint256 batchId, bytes memory poe) public {
        (bytes32 batchHash, bytes32 stateHash, bytes32 prevStateRoot, bytes32 newStateRoot, bytes32 withdrawalRoot, bytes memory sig) = abi.decode(poe, (bytes32, bytes32, bytes32, bytes32, bytes32, bytes));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(sig);
        bytes32 msgHash = keccak256(abi.encode(batchHash, stateHash, prevStateRoot, newStateRoot, withdrawalRoot, new bytes(65)));
        address signer = ecrecover(msgHash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");
        require(attestedProvers[signer] + attestValiditySeconds > block.timestamp, "Prover not attested");
        require(batches[batchHash].newStateRoot == bytes32(0), "batch already commit");
        batches[batchHash].newStateRoot = newStateRoot;
        batches[batchHash].prevStateRoot = prevStateRoot;
        batches[batchHash].withdrawalRoot = withdrawalRoot;
        emit CommitBatch(batchId, batchHash);
    }

    function submitProof(bytes memory report) public {
        (bytes32 blockHash, bytes32 stateHash, bytes32 prevStateRoot, bytes32 newStateRoot, bytes32 withdrawalRoot, bytes memory sig) = abi.decode(report, (bytes32, bytes32, bytes32, bytes32, bytes32, bytes));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(sig);

        require(prevStateRoot == currentStateRoot || currentStateRoot == bytes32(0), "prevStateRoot not match");

        bytes32 msgHash = keccak256(abi.encode(blockHash, stateHash, prevStateRoot, newStateRoot, withdrawalRoot, new bytes(65)));
        address signer = ecrecover(msgHash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");
        
        require(attestedProvers[signer] + attestValiditySeconds > block.timestamp, "Prover not attested");
        currentStateRoot = newStateRoot;
        currentWithdrawalRoot = withdrawalRoot;
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "invalid v value");
    }

    function verifyAttestation(bytes calldata data) view public returns (bool) {
        return dcapAttestation.verifyAttestation(data);
    }
}