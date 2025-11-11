// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/SignatureChecker.sol)

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @dev Signature verification helper that supports both ECDSA signatures from externally owned accounts (EOAs)
 * and ERC1271 signatures from smart contract wallets. Contract signers (ERC1271) must be whitelisted via
 * the access control system to prevent unauthorized contract-based signatures.
 *
 * This provides an additional security layer over standard SignatureChecker by requiring explicit trust
 * for contract signers while maintaining permissionless support for EOA signatures.
 */
library TrustedSignatureChecker {
    /**
     * @dev Checks if a signature is valid for a given signer and data hash.
     *
     * For EOA signers: Validates using ECDSA.recover (no whitelist required)
     * For contract signers: Validates using ERC1271 AND checks whitelist via accessControl.hasTrustedContractRole()
     *
     * @param signer The address claiming to have signed the hash
     * @param hash The hash that was signed
     * @param signature The signature bytes
     * @param accessControl The contract that implements hasTrustedContractRole(address) for whitelist checks
     * @return bool True if signature is valid and (for contracts) signer is whitelisted
     *
     * NOTE: Contract signatures are revocable and whitelist status can change between blocks.
     */

    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature, address accessControl)
        internal
        view
        returns (bool)
    {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        if (error == ECDSA.RecoverError.NoError && recovered == signer) {
            return true;
        }
        // only allow trusted ERC1271 signer - call hasTrustedContractRole instead of hasRole
        (bool success, bytes memory trustedContractResult) =
            accessControl.staticcall(abi.encodeWithSignature("hasTrustedContractRole(address)", signer));
        if (success && trustedContractResult.length == 32 && abi.decode(trustedContractResult, (bool))) {
            (bool _success, bytes memory result) =
                signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
            return (
                _success && result.length == 32
                    && abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector)
            );
        }
        return false;
    }
}
