// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../interfaces/ISigVerifyLib.sol";
import "./RsaVerify.sol";
import "./EllipticCurveLib.sol";
import "./BytesUtils.sol";

contract SigVerifyLib is ISigVerifyLib {
    using BytesUtils for bytes;

    function verifyAttStmtSignature(bytes memory tbs, bytes memory signature, PublicKey memory publicKey, Algorithm alg)
        public
        view
        returns (bool)
    {
        if (alg == Algorithm.RS256) {
            if (publicKey.keyType != KeyType.RSA) {
                return false;
            }
            return verifyRS256Signature(tbs, signature, publicKey.pubKey);
        } else if (alg == Algorithm.ES256) {
            if (publicKey.keyType != KeyType.ECDSA) {
                return false;
            }
            return verifyES256Signature(tbs, signature, publicKey.pubKey);
        } else if (alg == Algorithm.RS1) {
            if (publicKey.keyType != KeyType.RSA) {
                return false;
            }
            return verifyRS1Signature(tbs, signature, publicKey.pubKey);
        } else {
            revert("Unsupported algorithm");
        }
    }

    function verifyCertificateSignature(
        bytes memory tbs,
        bytes memory signature,
        PublicKey memory publicKey,
        CertSigAlgorithm alg
    ) public view returns (bool) {
        if (alg == CertSigAlgorithm.Sha256WithRSAEncryption) {
            if (publicKey.keyType != KeyType.RSA) {
                return false;
            }
            return verifyRS256Signature(tbs, signature, publicKey.pubKey);
        } else if (alg == CertSigAlgorithm.Sha1WithRSAEncryption) {
            if (publicKey.keyType != KeyType.RSA) {
                return false;
            }
            return verifyRS1Signature(tbs, signature, publicKey.pubKey);
        } else {
            revert("Unsupported algorithm");
        }
    }

    function verifyRS256Signature(bytes memory tbs, bytes memory signature, bytes memory publicKey)
        public
        view
        returns (bool sigValid)
    {
        // Parse public key
        bytes memory exponent = publicKey.substring(0, 3);
        bytes memory modulus = publicKey.substring(3, publicKey.length - 3);

        // Verify signature
        sigValid = RsaVerify.pkcs1Sha256Raw(tbs, signature, exponent, modulus);
    }

    function verifyRS1Signature(bytes memory tbs, bytes memory signature, bytes memory publicKey)
        public
        view
        returns (bool sigValid)
    {
        // Parse public key
        bytes memory exponent = publicKey.substring(0, 3);
        bytes memory modulus = publicKey.substring(3, publicKey.length - 3);

        // Verify signature
        sigValid = RsaVerify.pkcs1Sha1Raw(tbs, signature, exponent, modulus);
    }

    function verifyES256Signature(bytes memory tbs, bytes memory signature, bytes memory publicKey)
        public
        pure
        returns (bool sigValid)
    {
        // Parse signature
        if (signature.length != 64) {
            return false;
        }
        uint256 r = uint256(bytes32(signature.substring(0, 32)));
        uint256 s = uint256(bytes32(signature.substring(32, 32)));
        // Parse public key
        if (publicKey.length != 64) {
            return false;
        }
        uint256 gx = uint256(bytes32(publicKey.substring(0, 32)));
        uint256 gy = uint256(bytes32(publicKey.substring(32, 32)));

        // Verify signature
        sigValid = EllipticCurveLib.validateSignature(uint256(sha256(tbs)), gx, gy, r, s);
    }
}