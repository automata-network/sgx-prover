//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IAttestation {
    function verifyAttestation(bytes calldata data) view external returns (bool);
    function verifyMrEnclave(bytes32 _mrEnclave) view external returns (bool);
    function verifyMrSigner(bytes32 _mrSigner) view external returns (bool);
}