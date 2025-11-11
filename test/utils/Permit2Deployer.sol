// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IAllowanceTransfer} from "../../src/interface/permit2/IAllowanceTransfer.sol";
import {IPermit2} from "../../src/interface/permit2/IPermit2.sol";
import {IEIP712} from "../../src/interface/permit2/IEIP712.sol";

/// @notice Utility contract to deploy Permit2 in tests
/// @dev Fetches Permit2 bytecode from BSC mainnet and deploys at canonical address
abstract contract Permit2Deployer is Test {
    address public constant PERMIT2_ADDRESS = address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    IPermit2 public permit2;

    /// @notice Deploys Permit2 contract at canonical address using vm.etch
    /// @dev Loads bytecode from cached file, falls back to fetching via FFI if not found
    function deployPermit2() internal {
        string memory bytecodeFile = "./test/utils/permit2_bytecode.bin";
        bytes memory permit2Code;

        try vm.readFileBinary(bytecodeFile) returns (bytes memory cachedCode) {
            // File exists, use cached bytecode
            permit2Code = cachedCode;
        } catch {
            // File doesn't exist, fetch from BSC and cache it
            string memory bscRpc = vm.envOr("BNB_MAINNET_RPC_URL", string("https://bsc-dataseed.binance.org/"));

            string[] memory inputs = new string[](5);
            inputs[0] = "cast";
            inputs[1] = "code";
            inputs[2] = vm.toString(PERMIT2_ADDRESS);
            inputs[3] = "--rpc-url";
            inputs[4] = bscRpc;

            permit2Code = vm.ffi(inputs);

            // Cache for future use
            vm.writeFileBinary(bytecodeFile, permit2Code);
        }

        vm.etch(PERMIT2_ADDRESS, permit2Code);

        // Initialize permit2 instance
        permit2 = IPermit2(PERMIT2_ADDRESS);
    }

    function _createPermit2AllowanceDigest(
        address signer,
        address tokenAddress,
        address spenderAddress,
        uint160 amount,
        uint256 deadline
    ) internal view returns (bytes32 permitDigest) {
        // Get current nonce for this token/spender pair
        (,, uint48 nonce) = permit2.allowance(signer, tokenAddress, spenderAddress);

        // Hash PermitDetails struct
        bytes32 detailsHash = keccak256(
            abi.encode(
                keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"),
                tokenAddress,
                amount,
                type(uint48).max,
                nonce
            )
        );

        // Hash PermitSingle struct
        bytes32 permitHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
                ),
                detailsHash,
                spenderAddress,
                deadline
            )
        );

        // Get Permit2's domain separator
        bytes32 permit2DomainSeparator = IEIP712(PERMIT2_ADDRESS).DOMAIN_SEPARATOR();

        return keccak256(abi.encodePacked("\x19\x01", permit2DomainSeparator, permitHash));
    }

    function _signPermit2Allowance(
        uint256 privateKey,
        address signer,
        address tokenAddress,
        address spenderAddress,
        uint160 amount,
        uint256 deadline
    ) internal view returns (uint8, bytes32, bytes32) {
        bytes32 permitDigest = _createPermit2AllowanceDigest(signer, tokenAddress, spenderAddress, amount, deadline);
        return vm.sign(privateKey, permitDigest);
    }

    /// @notice Create Permit2 SignatureTransfer signature
    /// @dev Used for one-time token transfers via Permit2
    function _signPermit2SignatureTransfer(
        uint256 privateKey,
        address /* owner */,
        address tokenAddress,
        address spenderAddress,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 msgHash = _createPermit2SignatureTransferDigest(
            tokenAddress, spenderAddress, amount, nonce, deadline
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return abi.encodePacked(r, s, v);
    }

    function _createPermit2SignatureTransferDigest(
        address tokenAddress,
        address spenderAddress,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 tokenPermissions = keccak256(
            abi.encode(
                keccak256("TokenPermissions(address token,uint256 amount)"),
                tokenAddress,
                amount
            )
        );

        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                IEIP712(PERMIT2_ADDRESS).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"),
                        tokenPermissions,
                        spenderAddress,
                        nonce,
                        deadline
                    )
                )
            )
        );
    }
}
