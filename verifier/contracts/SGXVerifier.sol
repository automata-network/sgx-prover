// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {IAttestation} from "../interfaces/IAttestation.sol";

contract SGXVerifier {
    struct Pubkey {
        bytes32 x;
        bytes32 y;
    }

    struct Prover {
        Pubkey pubkey;
        uint256 time;
    }

    address public owner;
    mapping(bytes32 => bool) public attestedReports;
    mapping(bytes32 => Prover) public attestedProvers; // prover's pubkey => attestedTime

    uint256 public attestValiditySeconds = 3600;

    IAttestation public immutable dcapAttestation;
    uint256 public immutable layer2ChainId;

    uint256 public threshold = 1; // This is an example threshold. Adjust this value as needed.

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(address attestationAddr, uint256 _chainId) {
        owner = msg.sender;
        dcapAttestation = IAttestation(attestationAddr);
        layer2ChainId = _chainId;
    }

    function changeOwner(address _newOwner) public onlyOwner {
        owner = _newOwner;
    }

    function changeAttestValiditySeconds(uint256 val) public onlyOwner {
        attestValiditySeconds = val;
    }

    function verifyMrEnclave(bytes32 _mrenclave) public view returns (bool) {
        return dcapAttestation.verifyMrEnclave(_mrenclave);
    }

    function verifyMrSigner(bytes32 _mrsigner) public view returns (bool) {
        return dcapAttestation.verifyMrSigner(_mrsigner);
    }

    function register(bytes calldata report) public {
        (bool succ, bytes memory reportData) = dcapAttestation
            .verifyAttestation(report);
        require(succ, "attestation report validation fail");
        bytes32 reportHash = keccak256(report);
        require(!attestedReports[reportHash], "report is already used");

        (bytes32 x, bytes32 y) = splitBytes64(reportData);
        Pubkey memory pubkey = Pubkey(x, y);
        Prover memory prover = Prover(pubkey, block.timestamp);
        attestedProvers[keccak256(abi.encode(x, y))] = prover;
        attestedReports[reportHash] = true;
    }

    function isProverRegistered(
        bytes32 pubkeyX,
        bytes32 pubkeyY
    ) public view returns (bool) {
        bytes32 signer = keccak256(abi.encode(pubkeyX, pubkeyY));
        return
            attestedProvers[signer].time + attestValiditySeconds >
            block.timestamp;
    }

    function verifyAttestation(
        bytes32 pubkeyX,
        bytes32 pubkeyY,
        bytes calldata data
    ) public view returns (bool) {
        (bool succ, bytes memory reportData) = dcapAttestation
            .verifyAttestation(data);
        if (!succ) {
            return false;
        }

        (bytes32 x, bytes32 y) = splitBytes64(reportData);
        if (x != pubkeyX || y != pubkeyY) {
            return false;
        }

        return true;
    }

    function splitBytes64(
        bytes memory b
    ) private pure returns (bytes32, bytes32) {
        require(b.length >= 64, "Bytes array too short");

        bytes32 x;
        bytes32 y;
        assembly {
            x := mload(add(b, 32))
            y := mload(add(b, 64))
        }
        return (x, y);
    }
}
