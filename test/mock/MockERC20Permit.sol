// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../../src/interface/IEIP3009.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
// Mock ERC20 token for testing with EIP-2612 permit support and EIP-3009 meta-transactions
// Based on Circle's USDC implementation

contract MockERC20Permit is ERC20, IEIP3009 {
    using ECDSA for bytes32;

    mapping(address => uint256) private _nonces;
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;
    bytes32 private immutable _DOMAIN_SEPARATOR;
    string public constant version = "1";
    uint8 private _decimals;

    // EIP-2612 permit type hash
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // EIP-3009 type hashes - using Circle's official values
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;
    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;
    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    constructor(string memory name, string memory symbol, uint8 decimals_, uint256 _initialSupply)
        ERC20(name, symbol)
    {
        _mint(msg.sender, _initialSupply);
        _decimals = decimals_;

        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function nonces(address owner) external view returns (uint256) {
        return _nonces[owner];
    }

    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function decimals() public view override(ERC20, IEIP3009) returns (uint8) {
        return _decimals;
    }

    // EIP-3009: Check authorization state
    function authorizationState(address authorizer, bytes32 nonce) external view override returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    // EIP-2612 permit with proper signature verification
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
    {
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _nonces[owner]++, deadline));

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
        address signer = hash.recover(v, r, s);
        require(signer == owner, "ERC20Permit: invalid signature");

        _approve(owner, spender, value);
    }

    // EIP-3009: Transfer with authorization - following Circle's pattern
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)),
            abi.encodePacked(r, s, v)
        );

        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    // EIP-3009: Receive with authorization - following Circle's pattern
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {
        require(to == msg.sender, "MockERC20: caller must be the payee");
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)),
            abi.encodePacked(r, s, v)
        );

        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    // EIP-3009: Cancel authorization - following Circle's pattern
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external override {
        _requireUnusedAuthorization(authorizer, nonce);
        _requireValidSignature(
            authorizer,
            keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)),
            abi.encodePacked(r, s, v)
        );

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    // Placeholder for claim function (required by interface)
    function claim(uint256) external pure override {
        revert("Claim not implemented in mock");
    }

    // Override required functions from interface
    function transferFrom(address from, address to, uint256 value) public override(ERC20, IEIP3009) returns (bool) {
        return super.transferFrom(from, to, value);
    }

    function transfer(address to, uint256 value) public override(ERC20, IEIP3009) returns (bool) {
        return super.transfer(to, value);
    }

    // Internal helper functions following Circle's pattern
    function _requireValidSignature(address signer, bytes32 dataHash, bytes memory signature) private view {
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, dataHash));
        address recoveredSigner = hash.recover(signature);
        require(recoveredSigner == signer, "MockERC20: invalid signature");
    }

    function _requireUnusedAuthorization(address authorizer, bytes32 nonce) private view {
        require(!_authorizationStates[authorizer][nonce], "MockERC20: authorization is used or canceled");
    }

    function _requireValidAuthorization(address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore)
        private
        view
    {
        require(block.timestamp > validAfter, "MockERC20: authorization is not yet valid");
        require(block.timestamp < validBefore, "MockERC20: authorization is expired");
        _requireUnusedAuthorization(authorizer, nonce);
    }

    function _markAuthorizationAsUsed(address authorizer, bytes32 nonce) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }
}
