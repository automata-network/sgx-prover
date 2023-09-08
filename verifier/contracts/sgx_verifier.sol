// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

contract SGXVerifier {
    
    event RequestAttestation(bytes32 hash);
    event ProverApproved(address prover);
    event AddAttestor(address attestor);

    address public owner;
    mapping(address => bool) public attestors;
    mapping(bytes32 => Report) public reports;
    mapping(address => uint256) public attestedProvers; // prover's pubkey => attestedTime

    uint256 public attestValiditySeconds = 300;
    bytes32 public currentStateRoot;
    bytes32 public currentWithdrawalRoot;

    struct Report {
        uint approved;
        address prover;
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
    
    constructor() {
        owner = msg.sender;
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
    
    function submitAttestationReport(address prover, bytes memory reportBytes) public {
        bytes32 reportHash = keccak256(reportBytes);
        reports[reportHash].prover = prover;
        emit RequestAttestation(reportHash);
    }

    function challengeReport(address attestor, bool approve, bytes memory reportBytes) public {
        bytes32 reportHash = keccak256(reportBytes);
        uint vote = reports[reportHash].votes[attestor];
        require(vote != 0, "invalid votes");
        require((vote == 1 && !approve) || (vote == 2 && approve), "invalid challenge");


        // TODO: validate the report on chain
        // Assuming the challenge is successful

        if (!approve) {
            uint approved = reports[reportHash].approved;
            approved -= 1;
            reports[reportHash].approved = approved; // revert the vote
            if (approved < threshold) {
                attestedProvers[reports[reportHash].prover] = 0;
            }
        }
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
}