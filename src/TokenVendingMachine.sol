// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "forge-std/console.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISignatureTransfer} from "./interface/permit2/ISignatureTransfer.sol";

contract TokenVendingMachine is
    Initializable,
    AccessControlEnumerableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    address public constant PERMIT2_ADDRESS = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    event CheckoutSuccess(address indexed caller, bytes32 indexed checkoutMessageHash);
    event BuybackSuccess(bytes32 indexed checkoutMessageHash, address token, uint256 indexed amount);

    struct BuyerAuthorization {
        bytes32 checkoutId; // Must match the checkout request (32 bytes - slot 0)
        bytes32 permitR; // Permit signature r (32 bytes - slot 1)
        bytes32 permitS; // Permit signature s (32 bytes - slot 2)
        address token; // the token to be purchased (20 bytes - slot 3)
        uint48 permitDeadline; // Permit deadline timestamp (6 bytes - packed in slot 3)
        uint8 permitV; // Permit signature v (1 byte - packed in slot 3)
        uint256 nonce; // Permit2 nonce (32 bytes - slot 4)
        uint256 amount; // the amount of tokens to be purchased (32 bytes - slot 5)
    }

    struct BuybackAuthorization {
        bytes32 checkoutId; // Must match the checkout request (32 bytes - slot 0)
        address token; // the token to be purchased (20 bytes - slot 1)
        uint256 amount; // the amount of tokens to be purchased (32 bytes - slot 2)
    }

    // mapping of all the checkout message to the address that authorized the checkout. if address = address(this), the checkout was buybacked.
    mapping(bytes32 => address) checkoutAuth;
    mapping(bytes32 => bytes32) merkleRoots; // mapping of all the merkle roots for each pack.

    /* ========================================== CONSTRUCTOR AND SETTERS ========================================== */

    /**
     * @dev initializer.
     */
    function initialize() public initializer {
        __AccessControlEnumerable_init();
        // Set the admin
        AccessControlEnumerableUpgradeable._grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract.
     * Called by {upgradeTo} and {upgradeToAndCall}.
     * @param newImplementation address of the new implementation
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    /**
     * @dev Returns the implementation of this contract.
     */
    function implementation() external view returns (address) {
        return _getImplementation();
    }

    /* =================================== ROLE HELPERS AND FUNCTIONS OVERRIDES =================================== */

    /**
     * @dev remove external access to {AccessControl.grantRole}.
     */
    function grantRole(bytes32, address) public pure override(AccessControlUpgradeable, IAccessControlUpgradeable) {
        revert("TokenVendingMachine: A role can only be granted using the corresponding specialized function");
    }

    /**
     * @dev remove external access to {AccessControl.revokeRole}.
     */
    function revokeRole(bytes32, address) public pure override(AccessControlUpgradeable, IAccessControlUpgradeable) {
        revert("TokenVendingMachine: A role can only be revoked using the corresponding specialized function");
    }

    /**
     * @dev list the addresses that have a particular role.
     */
    function listRoleMembers(bytes32 role) public view returns (address[] memory) {
        uint256 memberCount = getRoleMemberCount(role);
        address[] memory members = new address[](memberCount);
        for (uint256 ii = 0; ii < memberCount; ii++) {
            members[ii] = getRoleMember(role, ii);
        }
        return members;
    }

    /* ================================================ ADMIN ROLE ================================================ */

    /**
     * @dev Modifier that checks that the sender has the {DEFAULT_ADMIN_ROLE} role.
     */
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "TokenVendingMachine: Caller is missing role ADMIN.");
        _;
    }

    /**
     * @dev transfer the {DEFAULT_ADMIN_ROLE} role to another wallet.
     *
     * note: because {grantRole} and {revokeRole} are not accessible externally, this function ensures that there
     * can only be a single admin for this contract at any time.
     */
    function transferAdmin(address _to) public onlyAdmin {
        super.grantRole(DEFAULT_ADMIN_ROLE, _to);
        super.revokeRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**
     * @dev returns the address of the admin of this registry.
     */
    function admin() public view returns (address) {
        return getRoleMember(DEFAULT_ADMIN_ROLE, 0);
    }

    /* ================================================ CHECKOUT ORACLE ROLE ================================================ */

    /**
     * @dev the trusted checkout oracle role.
     */
    function TRUSTED_CHECKOUT_ORACLE_ROLE() internal pure returns (bytes32) {
        return keccak256("TRUSTED_CHECKOUT_ORACLE_ROLE");
    }

    /**
     * @dev grant the TRUSTED_CHECKOUT_ORACLE_ROLE role that allows an account to provide minting signatures for minting tokens.
     */
    function addTrustedCheckoutOracle(address account) public onlyAdmin {
        super.grantRole(TRUSTED_CHECKOUT_ORACLE_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_CHECKOUT_ORACLE_ROLE role.
     */
    function removeTrustedCheckoutOracle(address account) public onlyAdmin {
        super.revokeRole(TRUSTED_CHECKOUT_ORACLE_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_CHECKOUT_ORACLE_ROLE} role.
     */
    function isTrustedCheckoutOracle(address account) public view returns (bool) {
        return hasRole(TRUSTED_CHECKOUT_ORACLE_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_CHECKOUT_ORACLE_ROLE} role.
     */
    function listTrustedCheckoutOracles() public view returns (address[] memory) {
        return listRoleMembers(TRUSTED_CHECKOUT_ORACLE_ROLE());
    }

    /* ================================================ CHECKOUT ORACLE ROLE ================================================ */

    /**
     * @dev the trusted checkout oracle role.
     */
    function TRUSTED_BUY_BACK_ROLE() internal pure returns (bytes32) {
        return keccak256("TRUSTED_BUY_BACK_ROLE");
    }

    /**
     * @dev @dev Check that a specific address is a trusted checkout oracle.
     */
    modifier onlyTrustedBuybackRole() {
        require(
            hasRole(TRUSTED_BUY_BACK_ROLE(), msg.sender),
            "TokenVendingMachine: Caller is missing role TRUSTED_BUY_BACK_ROLE."
        );
        _;
    }

    /**
     * @dev grant the TRUSTED_BUY_BACK_ROLE role that allows an account to buyback from checkout request.
     */
    function addTrustedBuybackRole(address account) public onlyAdmin {
        super.grantRole(TRUSTED_BUY_BACK_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_BUY_BACK_ROLE role.
     */
    function removeTrustedBuybackRole(address account) public onlyAdmin {
        super.revokeRole(TRUSTED_BUY_BACK_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_BUY_BACK_ROLE} role.
     */
    function isTrustedBuybackRole(address account) public view returns (bool) {
        return hasRole(TRUSTED_BUY_BACK_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_BUY_BACK_ROLE} role.
     */
    function listTrustedBuybackRoles() public view returns (address[] memory) {
        return listRoleMembers(TRUSTED_BUY_BACK_ROLE());
    }

    /* ========================================== TRUSTED CALLER ROLE ========================================== */

    /**
     * @dev returns the role hash for TRUSTED_CALLER_ROLE.
     */
    function TRUSTED_CALLER_ROLE() internal pure returns (bytes32) {
        return keccak256("TRUSTED_CALLER_ROLE");
    }

    /**
     * @dev grant the TRUSTED_CALLER_ROLE role that allows an account to execute transactions on behalf of buyers.
     */
    function addTrustedCaller(address account) public onlyAdmin {
        super.grantRole(TRUSTED_CALLER_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_CALLER_ROLE role.
     */
    function removeTrustedCaller(address account) public onlyAdmin {
        super.revokeRole(TRUSTED_CALLER_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_CALLER_ROLE} role.
     */
    function isTrustedCaller(address account) public view returns (bool) {
        return hasRole(TRUSTED_CALLER_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_CALLER_ROLE} role.
     */
    function listTrustedCallers() public view returns (address[] memory) {
        return listRoleMembers(TRUSTED_CALLER_ROLE());
    }

    /* ========================================= CHECKOUT REQUEST HELPERS ========================================= */

    /**
     * @dev recover signer from signed message.
     * @param data the checkout request as bytes.
     * @param signature the signature block of {data}, signed by a trusted checkout oracle.
     */
    function _recoverSignerFromSignedMessage(bytes calldata data, bytes calldata signature)
        internal
        view
        returns (address)
    {
        bytes32 expectedSignedMessage = ECDSA.toEthSignedMessageHash(data);
        address recoveredSigner = ECDSA.recover(expectedSignedMessage, signature);
        return recoveredSigner;
    }

    /* ============================================ CHECKOUT ID HELPERS ============================================ */

    /**
     * @dev helper to check if a checkoutId is processed and not buybacked.
     * @param checkoutMessageHash the checkout message hash (bytes32 hash).
     * @return true if {checkoutId} has been processed, false otherwise.
     */
    function current(bytes32 checkoutMessageHash) public view returns (bool) {
        return checkoutAuth[checkoutMessageHash] != address(0) && checkoutAuth[checkoutMessageHash] != address(this);
    }

    /**
     * @dev helper to check if a checkoutId exists, i.e. if the checkout for that id was completed.
     * @param checkoutMessageHash the checkout message hash (bytes32 hash).
     * @return true if {checkoutId} has been processed, false otherwise.
     */
    function exists(bytes32 checkoutMessageHash) public view returns (bool) {
        return checkoutAuth[checkoutMessageHash] != address(0);
    }

    /* ============================================== ERC20 CHECKOUT ============================================== */

    /**
     * @dev Hash the buyer authorization for signature verification
     */
    function _hashBuyerAuthorization(BuyerAuthorization memory auth) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(auth.token, auth.amount, auth.nonce, auth.permitDeadline, auth.permitV, auth.permitR, auth.permitS)
        );
    }

    /**
     * @dev Execute checkout with buyer authorization using EIP-2612 permit.
     * This function allows a trusted caller to execute a transaction on behalf of a buyer.
     * Supports permit-based (gasless) payment where buyer signs EIP-2612 permit.
     *
     * Requirements:
     *  - caller must have TRUSTED_CALLER_ROLE
     *  - the contract is not paused
     *  - the checkout message must be signed by both trusted oracle and buyer
     *  - buyer must sign authorization containing checkoutId and permit signature components
     *  - checkout message hash must not have been processed before
     *  - buyer recovered from checkout signature must match buyer recovered from auth signature
     *
     * Payment Method:
     *  - Permit-based (gasless): Buyer signs EIP-2612 permit
     *    - permitV, permitR, permitS must contain valid ECDSA signature
     *    - permitDeadline must be valid timestamp
     *    - Contract will call permit() then transferFrom()
     *
     * @param checkoutMessage The checkout message data
     * @param buyerCheckoutSignature Buyer's signature of the checkout message
     * @param trustedOracleCheckoutSignature Oracle's signature of the checkout message
     * @param buyerAuthData Encoded BuyerAuthorization struct
     * @param buyerAuthSignature Buyer's signature of the authorization data
     */
    function permitFunds(
        bytes calldata checkoutMessage,
        bytes calldata buyerCheckoutSignature,
        bytes calldata trustedOracleCheckoutSignature,
        bytes calldata buyerAuthData,
        bytes calldata buyerAuthSignature
    ) external onlyRole(TRUSTED_CALLER_ROLE()) {
        require(
            isTrustedCheckoutOracle(_recoverSignerFromSignedMessage(checkoutMessage, trustedOracleCheckoutSignature)),
            "TokenVendingMachine: Invalid signature."
        );
        address buyer = _recoverSignerFromSignedMessage(checkoutMessage, buyerCheckoutSignature);
        require(
            buyer == _recoverSignerFromSignedMessage(buyerAuthData, buyerAuthSignature),
            "TokenVendingMachine: Invalid buyer signature."
        );
        BuyerAuthorization memory buyerAuth = abi.decode(buyerAuthData, (BuyerAuthorization));
        bytes32 checkoutMessageHash = keccak256(checkoutMessage);
        require(buyerAuth.checkoutId == checkoutMessageHash, "TokenVendingMachine: CheckoutId mismatch.");
        require(!exists(checkoutMessageHash), "TokenVendingMachine: Checkout with checkoutId was already processed.");

        // Use Permit2 SignatureTransfer to pull funds
        ISignatureTransfer PERMIT2 = ISignatureTransfer(PERMIT2_ADDRESS);

        PERMIT2.permitTransferFrom(
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({
                    token: buyerAuth.token,
                    amount: buyerAuth.amount
                }),
                nonce: buyerAuth.nonce,
                deadline: uint256(buyerAuth.permitDeadline)
            }),
            ISignatureTransfer.SignatureTransferDetails({
                to: address(this),
                requestedAmount: buyerAuth.amount
            }),
            buyer,
            bytes.concat(buyerAuth.permitR, buyerAuth.permitS, bytes1(buyerAuth.permitV))
        );

        checkoutAuth[checkoutMessageHash] = buyer;
        emit CheckoutSuccess(buyer, checkoutMessageHash);
    }

    // Buyback the checkout request by buyback admin.
    function buyback(bytes32 checkoutMessageHash, bytes calldata buybackAuthData, bytes calldata buybackAuthSignature)
        external
        onlyRole(TRUSTED_BUY_BACK_ROLE())
    {
        BuybackAuthorization memory buybackAuth = abi.decode(buybackAuthData, (BuybackAuthorization));
        require(current(checkoutMessageHash), "checkout status invalid");
        address buyer = checkoutAuth[checkoutMessageHash];

        require(
            _recoverSignerFromSignedMessage(buybackAuthData, buybackAuthSignature) == buyer,
            "TokenVendingMachine: Invalid buyback signature."
        );

        checkoutAuth[checkoutMessageHash] = address(this);
        IERC20(buybackAuth.token).safeTransferFrom(msg.sender, address(this), buybackAuth.amount);
        IERC20(buybackAuth.token).safeTransfer(buyer, buybackAuth.amount);

        emit BuybackSuccess(checkoutMessageHash, buybackAuth.token, buybackAuth.amount);
    }

    /* ============================================== MERKLE PROOF HELPERS ============================================== */

    /**
     * @dev Set the merkle root for a pack.
     * @param packId The pack identifier
     * @param merkleRoot The merkle root hash
     */
    function setMerkleRoot(bytes32 packId, bytes32 merkleRoot) public onlyAdmin {
        merkleRoots[packId] = merkleRoot;
    }

    /**
     * @dev Get the merkle root for a pack.
     * @param packId The pack identifier
     * @return The merkle root hash
     */
    function getMerkleRoot(bytes32 packId) public view returns (bytes32) {
        bytes32 root = merkleRoots[packId];
        require(root != bytes32(0), "TokenVendingMachine: Merkle root not set for this pack");
        return root;
    }

    /**
     * @dev Verify a merkle proof for a given leaf and pack.
     * @param packId The pack identifier
     * @param proof The merkle proof array
     * @param leaf The leaf node to verify
     * @return True if the proof is valid, false otherwise
     */
    function verifyMerkleProof(bytes32 packId, bytes32[] calldata proof, bytes32 leaf) public view returns (bool) {
        bytes32 root = getMerkleRoot(packId);
        return MerkleProof.verify(proof, root, leaf);
    }

    /* ============================================== FUND WITHDRAWAL ============================================== */

    /**
     * @dev Withdraw ERC20 tokens from the contract that were deposited via permitFunds.
     * Only callable by admin.
     * @param token The ERC20 token address to withdraw
     * @param to The address to send the tokens to
     * @param amount The amount of tokens to withdraw
     */
    function withdrawFunds(address token, address to, uint256 amount) external onlyAdmin {
        require(to != address(0), "TokenVendingMachine: Cannot withdraw to zero address");
        require(amount > 0, "TokenVendingMachine: Amount must be greater than zero");
        IERC20(token).safeTransfer(to, amount);
    }
}
