// SPDX-License-Identifier: MIT

pragma solidity >=0.8.7;

// import "./DefaultOperatorFiltererUpgradeable.sol";
import "./interface/ITokenRegistryUpgradeable.sol";
import "./utils/MutableTokenURIUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC2981Upgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
import "./RoyaltyPaymentSplitter.sol";
import "./RoyaltyPaymentSplitterFactory.sol";
import "solady/utils/EfficientHashLib.sol";

/**
 * @author The Renaiss Team
 * @title {RenaissRegistry} is a registry that holds ERC721 tokens and implements special actions around these tokens.
 */
contract RenaissRegistryV3 is
    Initializable,
    UUPSUpgradeable,
    ITokenRegistryUpgradeable,
    AccessControlEnumerableUpgradeable,
    ERC721EnumerableUpgradeable,
    IERC2981Upgradeable,
    // This inheritance can be called in any order because it contains only constants and functions (no state variables) and does not reserve any __gap
    // DefaultOperatorFiltererUpgradeable, // commented now as OperatorFilter from opensea not implemented in our chain
    MutableTokenURIUpgradeable,
    PausableUpgradeable
{
    using Strings for uint256;

    event ReplacedFaultyToken(
        address indexed callingModerator,
        address indexed tokenOwner,
        bytes32 faultyProofOfIntegrity,
        bytes32 newProofOfIntegrity
    );
    event TokenRoyaltyUpdated(uint256 indexed tokenId, address indexed receiver, uint96 feeNumerator);

    // ERC2981 implementation storage
    struct RoyaltyInfo {
        address receiver;
        uint96 royaltyFraction;
    }

    mapping(uint256 => RoyaltyInfo) private _tokenRoyaltyInfo;
    uint96 _defaultRoyaltyFeeBps;
    address public treasury;
    address public royaltyPaymentSplitterFactory;

    /**
     * @dev initializer for deployment when using the upgradeability pattern.
     */
    function initialize(
        address contractAdmin,
        string memory uri,
        string memory tokenName,
        string memory tokenSymbol,
        address _treasury
    ) public initializer {
        ERC721Upgradeable.__ERC721_init(tokenName, tokenSymbol);
        __UUPSUpgradeable_init();
        // DefaultOperatorFiltererUpgradeable.__DefaultOperatorFilterer_init();
        MutableTokenURIUpgradeable.__MutableTokenURI_init(uri);
        PausableUpgradeable.__Pausable_init();
        AccessControlUpgradeable._grantRole(DEFAULT_ADMIN_ROLE, contractAdmin);
        _defaultRoyaltyFeeBps = 100;
        treasury = _treasury;
    }

    function setRoyaltyPaymentSplitterFactory(address _royaltyPaymentSplitterFactory) public onlyAdmin {
        royaltyPaymentSplitterFactory = _royaltyPaymentSplitterFactory;
        RoyaltyPaymentSplitterFactory(royaltyPaymentSplitterFactory).registryContractSigningIn();
    }

    /**
     * @dev See {UUPSUpgradeable-_authorizeUpgrade}.
     */
    function _authorizeUpgrade(address) internal virtual override onlyAdmin {}

    /**
     * @dev Returns the implementation of this contract.
     */
    function implementation() external view returns (address) {
        return _getImplementation();
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerableUpgradeable, ERC721EnumerableUpgradeable, IERC165Upgradeable)
        returns (bool)
    {
        return interfaceId == type(ITokenRegistryUpgradeable).interfaceId
            || interfaceId == type(IERC2981Upgradeable).interfaceId || super.supportsInterface(interfaceId);
    }

    /* =================================== ROLE HELPERS AND FUNCTIONS OVERRIDES =================================== */

    /**
     * @dev remove external access to {AccessControlUpgradeable.grantRole}.
     */
    function grantRole(bytes32, address) public pure override(AccessControlUpgradeable, IAccessControlUpgradeable) {
        revert("RenaissRegistry: A role can only be granted using the corresponding specialized function");
    }

    /**
     * @dev remove external access to {AccessControlUpgradeable.revokeRole}.
     */
    function revokeRole(bytes32, address) public pure override(AccessControlUpgradeable, IAccessControlUpgradeable) {
        revert("RenaissRegistry: A role can only be revoked using the corresponding specialized function");
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
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "RenaissRegistry: Caller is missing role ADMIN.");
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
    function admin() external view returns (address) {
        return getRoleMember(DEFAULT_ADMIN_ROLE, 0);
    }

    /**
     * @dev same as {admin()}, to support Dapps that use {owner()} rather than {admin()} to check the ownership of
     * a contract.
     */
    function owner() external view returns (address) {
        return getRoleMember(DEFAULT_ADMIN_ROLE, 0);
    }

    /* ================================================ MINTER ROLE ================================================ */

    /**
     * @dev the minter role.
     */
    function MINTER_ROLE() private pure returns (bytes32 role) {
        return EfficientHashLib.hash(bytes32("MINTER_ROLE"));
    }

    /**
     * @dev Modifier that checks that the sender has the {MINTER_ROLE} role.
     */
    modifier onlyMinter() {
        require(hasRole(MINTER_ROLE(), _msgSender()), "RenaissRegistry: Caller is missing role MINTER_ROLE.");
        _;
    }

    /**
     * @dev grant the MINTER_ROLE role that allows to minting new tokens.
     */
    function grantMinterRole(address account) public onlyAdmin {
        super.grantRole(MINTER_ROLE(), account);
    }

    /**
     * @dev revoke the MINTER_ROLE role.
     */
    function revokeMinterRole(address account) public onlyAdmin {
        super.revokeRole(MINTER_ROLE(), account);
    }

    /**
     * @dev check if an address has the {MINTER_ROLE} role.
     */
    function hasMinterRole(address account) public view returns (bool) {
        return hasRole(MINTER_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {MINTER_ROLE} role.
     */
    function listMinterRoleMembers() public view returns (address[] memory) {
        return listRoleMembers(MINTER_ROLE());
    }

    /* ================================================ BURNER ROLE ================================================ */

    /**
     * @dev the burner role.
     */
    function BURNER_ROLE() private pure returns (bytes32 role) {
        return EfficientHashLib.hash(bytes32("BURNER_ROLE"));
    }

    /**
     * @dev Modifier that checks that the sender has the {BURNER_ROLE} role.
     */
    modifier onlyBurner() {
        require(hasRole(BURNER_ROLE(), _msgSender()), "RenaissRegistry: Caller is missing role BURNER_ROLE.");
        _;
    }

    /**
     * @dev grant the BURNER_ROLE role that allows to minting new tokens.
     */
    function grantBurnerRole(address account) public onlyAdmin {
        super.grantRole(BURNER_ROLE(), account);
    }

    /**
     * @dev revoke the BURNER_ROLE role.
     */
    function revokeBurnerRole(address account) public onlyAdmin {
        super.revokeRole(BURNER_ROLE(), account);
    }

    /**
     * @dev check if an address has the {BURNER_ROLE} role.
     */
    function hasBurnerRole(address account) public view returns (bool) {
        return hasRole(BURNER_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {BURNER_ROLE} role.
     */
    function listBurnerRoleMembers() public view returns (address[] memory) {
        return listRoleMembers(BURNER_ROLE());
    }

    /* =========================================== TOKEN MODERATOR ROLE =========================================== */

    /**
     * @dev the token moderator role.
     * An "token moderator" will typically have some superpowers over a token when there is an absolute necessity
     * to manipulate such token.
     */
    function TOKEN_MODERATOR_ROLE() private pure returns (bytes32 role) {
        return EfficientHashLib.hash(bytes32("TOKEN_MODERATOR_ROLE"));
    }

    /**
     * @dev Modifier that checks that the sender has the {TOKEN_MODERATOR_ROLE} role.
     */
    modifier onlyTokenModerator() {
        require(
            hasRole(TOKEN_MODERATOR_ROLE(), _msgSender()),
            "RenaissRegistry: Caller is missing role TOKEN_MODERATOR_ROLE."
        );
        _;
    }

    /**
     * @dev grant the TOKEN_MODERATOR_ROLE role.
     */
    function grantTokenModeratorRole(address account) public onlyAdmin {
        super.grantRole(TOKEN_MODERATOR_ROLE(), account);
    }

    /**
     * @dev revoke the TOKEN_MODERATOR_ROLE role.
     */
    function revokeTokenModeratorRole(address account) public onlyAdmin {
        super.revokeRole(TOKEN_MODERATOR_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TOKEN_MODERATOR_ROLE} role.
     */
    function hasTokenModeratorRole(address account) public view returns (bool) {
        return hasRole(TOKEN_MODERATOR_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TOKEN_MODERATOR_ROLE} role.
     */
    function listTokenModeratorRoleMembers() public view returns (address[] memory) {
        return listRoleMembers(TOKEN_MODERATOR_ROLE());
    }

    /* ========================================== ACCOUNT MODERATOR ROLE ========================================== */

    /**
     * @dev the account moderator role.
     * An "account moderator" will typically have some superpowers over accounts, to mark them as banned for instance.
     */
    function ACCOUNT_MODERATOR_ROLE() private pure returns (bytes32) {
        return keccak256("ACCOUNT_MODERATOR_ROLE");
    }

    /**
     * @dev Modifier that checks that the sender has the {ACCOUNT_MODERATOR_ROLE} role.
     */
    modifier onlyAccountModerator() {
        require(
            hasRole(ACCOUNT_MODERATOR_ROLE(), _msgSender()),
            "RenaissRegistry: Caller is missing role ACCOUNT_MODERATOR_ROLE."
        );
        _;
    }

    /**
     * @dev ensure that the ACCOUNT_MODERATOR_ROLE has the ability to manage banned accounts.
     * This only needs to be called once after the BANNED_ACCOUNT account role is introduced in an
     * upgrade, to avoid hiccups. This is not clean, but the alternative would be headache inducing.
     */
    function grantAccountModeratorRoleAccountBanningPower() public onlyAdmin {
        _setRoleAdmin(BANNED_ACCOUNT(), ACCOUNT_MODERATOR_ROLE());
    }

    /**
     * @dev grant the ACCOUNT_MODERATOR_ROLE role.
     */
    function grantAccountModeratorRole(address account) public onlyAdmin {
        super.grantRole(ACCOUNT_MODERATOR_ROLE(), account);
    }

    /**
     * @dev revoke the ACCOUNT_MODERATOR_ROLE role.
     */
    function revokeAccountModeratorRole(address account) public onlyAdmin {
        super.revokeRole(ACCOUNT_MODERATOR_ROLE(), account);
    }

    /**
     * @dev check if an address has the {ACCOUNT_MODERATOR_ROLE} role.
     */
    function hasAccountModeratorRole(address account) public view returns (bool) {
        return hasRole(ACCOUNT_MODERATOR_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {ACCOUNT_MODERATOR_ROLE} role.
     */
    function listAccountModeratorRoleMembers() public view returns (address[] memory) {
        return listRoleMembers(ACCOUNT_MODERATOR_ROLE());
    }

    /* ====================================== TRUSTED OPERATOR ROLE AND HELPERS ====================================== */

    /**
     * @dev the trusted operator role.
     * A trusted operator has the ability to manipulate tokens for the benefit of the owner.
     * The admin his responsible for only giving the {TRUSTED_OPERATOR_ROLE} role to trusted accounts.
     * Example of trusted operators: trusted marketplace contracts.
     */
    function TRUSTED_OPERATOR_ROLE() private pure returns (bytes32) {
        return keccak256("TRUSTED_OPERATOR_ROLE");
    }

    /**
     * @dev grant the TRUSTED_OPERATOR_ROLE role.
     */
    function grantTrustedOperatorRole(address account) public onlyAdmin {
        super.grantRole(TRUSTED_OPERATOR_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_OPERATOR_ROLE role.
     */
    function revokeTrustedOperatorRole(address account) public onlyAdmin {
        super.revokeRole(TRUSTED_OPERATOR_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_OPERATOR_ROLE} role.
     */
    function hasTrustedOperatorRole(address account) public view returns (bool) {
        return hasRole(TRUSTED_OPERATOR_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_OPERATOR_ROLE} role.
     */
    function listTrustedOperatorRoleMembers() public view returns (address[] memory) {
        return listRoleMembers(TRUSTED_OPERATOR_ROLE());
    }

    /**
     * @dev If the operator has the {TRUSTED_OPERATOR_ROLE}, it is pre-approved. Else see {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address targetOwner, address operator)
        public
        view
        virtual
        override(ERC721Upgradeable, IERC721Upgradeable)
        returns (bool)
    {
        return hasTrustedOperatorRole(operator) || super.isApprovedForAll(targetOwner, operator);
    }

    /* ====================================== TRUSTED FORWARDER ROLE AND HELPERS ====================================== */

    /**
     * @dev the trusted forwarder role.
     * An "trused forwarder" has the ability to execute transactions on behalf of an account as if the account was executing
     * those transactions. This is helpful to allow a relayer to run transactions on behalf of an account.
     */
    function TRUSTED_FORWARDER_ROLE() private pure returns (bytes32) {
        return keccak256("TRUSTED_FORWARDER_ROLE");
    }

    /**
     * @dev grant the TRUSTED_FORWARDER_ROLE role.
     */
    function grantTrustedForwarderRole(address account) public onlyAdmin {
        super.grantRole(TRUSTED_FORWARDER_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_FORWARDER_ROLE role.
     */
    function revokeTrustedForwarderRole(address account) public onlyAdmin {
        super.revokeRole(TRUSTED_FORWARDER_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_FORWARDER_ROLE} role.
     */
    function hasTrustedForwarderRole(address account) public view returns (bool) {
        return hasRole(TRUSTED_FORWARDER_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_FORWARDER_ROLE} role.
     */
    function listTrustedForwarderRoleMembers() public view returns (address[] memory) {
        return listRoleMembers(TRUSTED_FORWARDER_ROLE());
    }

    /**
     * @dev Override of {_msgSender()} that supports a trusted forwarder.
     * Heavily inspired from {openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol:ERC2771ContextUpgradeable}.
     */
    function _msgSender() internal view virtual override(ContextUpgradeable) returns (address sender) {
        if (hasTrustedForwarderRole(msg.sender)) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return super._msgSender();
        }
    }

    /**
     * @dev Override of {_msgData()} that supports a trusted forwarder.
     * Heavily inspired from {openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol:ERC2771ContextUpgradeable}.
     */
    function _msgData() internal view virtual override(ContextUpgradeable) returns (bytes calldata) {
        if (hasTrustedForwarderRole(msg.sender)) {
            return msg.data[:msg.data.length - 20];
        } else {
            return super._msgData();
        }
    }

    /* =========================================== ACCOUNT BANNING HELPERS =========================================== */

    /**
     * @dev a role to help ban accounts that show suspicious activity.
     */
    function BANNED_ACCOUNT() private pure returns (bytes32 role) {
        return EfficientHashLib.hash(bytes32("BANNED_ACCOUNT"));
    }

    /**
     * @dev Modifier that checks that an address is not banned.
     */
    modifier onlyWhenNotBanned(address account) {
        require(!hasRole(BANNED_ACCOUNT(), account), "RenaissRegistry: Banned account.");
        _;
    }

    /**
     * @dev Add an address to the list of banned accounts.
     */
    function banAccount(address account) public onlyAccountModerator {
        super.grantRole(BANNED_ACCOUNT(), account);
    }

    /**
     * @dev Unban an address by removing it from the list of banned accounts.
     */
    function unbanAccount(address account) public onlyAccountModerator {
        super.revokeRole(BANNED_ACCOUNT(), account);
    }

    /**
     * @dev check if an address is banned.
     */
    function isBannedAccount(address account) public view returns (bool) {
        return hasRole(BANNED_ACCOUNT(), account);
    }

    /**
     * @dev list the addresses that are banned.
     */
    function listBannedAccounts() public view returns (address[] memory) {
        return listRoleMembers(BANNED_ACCOUNT());
    }

    /* =============================== TOKEN TRANSFER HELPERS & OVERRIDES =============================== 
     * These include:
     * - DefaultOperatorFiltererUpgradeable overrides
     * - Pausability overrides
     * - Account banning overrides
     */

    function setApprovalForAll(address operator, bool approved)
        public
        override(ERC721Upgradeable, IERC721Upgradeable)
        // onlyAllowedOperatorApproval(operator)
        whenNotPaused
    {
        super.setApprovalForAll(operator, approved);
    }

    function approve(address operator, uint256 tokenId)
        public
        override(ERC721Upgradeable, IERC721Upgradeable)
        // onlyAllowedOperatorApproval(operator)
        whenNotPaused
    {
        super.approve(operator, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId)
        public
        override(ERC721Upgradeable, IERC721Upgradeable)
        // onlyAllowedOperator(from)
        whenNotPaused
        onlyWhenNotBanned(from)
        onlyWhenNotBanned(to)
    {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public
        override(ERC721Upgradeable, IERC721Upgradeable)
        // onlyAllowedOperator(from)
        whenNotPaused
        onlyWhenNotBanned(from)
        onlyWhenNotBanned(to)
    {
        super.safeTransferFrom(from, to, tokenId, data);
    }

    /**
     * @dev helper to transfer multiple tokens at once to another account.
     * note: no need to check for account banning here since if is already checked in {safeTransferFrom}.
     */
    function safeBatchTransferFrom(address from, address to, uint256[] memory tokenIds)
        public
        // onlyAllowedOperator(from)
        whenNotPaused
    {
        for (uint256 ii = 0; ii < tokenIds.length; ii++) {
            safeTransferFrom(from, to, tokenIds[ii]);
        }
    }

    /**
     * ======================================== TOKEN ID & PROOF OF INTEGRITY ========================================
     *
     * A token's Proof of Integrity is a 32 bytes hex value, which translates to a uint256 in a deterministic way.
     * This method saves about 27% in gas fees by using a direct translation {tokenId} <> {proofOfIntegrity}, rather
     * than storing the two attributes separately on chain.
     */

    /**
     * @dev Generates a Proof Of Integrity as the keccak256 hash of a human readable {fingerprint} and a {salt} value.
     */
    function generateProofOfIntegrity(string memory fingerprint, uint256 salt) public pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encodePacked(fingerprint, salt));
    }

    /**
     * @dev {tokenId} => {proofOfIntegrity} as a hex string.
     */
    function _tokenIdToProofOfIntegrityAsHexString(uint256 tokenId) private pure returns (string memory) {
        return tokenId.toHexString(32);
    }

    /**
     * @dev get the tokenId for a particular proof of Integrity.
     * See {ITokenRegistryUpgradeable-getTokenId}.
     * Requirement:
     *      - the token must exist.
     */
    function getTokenId(bytes32 proofOfIntegrity) public view returns (uint256) {
        uint256 tokenId = uint256(proofOfIntegrity);
        require(_exists(tokenId), "RenaissRegistry: Nonexistent token.");
        return tokenId;
    }

    /**
     * @dev get the Proof of Integrity of a particular token.
     * Requirement:
     *      - the token must exist.
     */
    function getTokenProofOfIntegrity(uint256 tokenId) public view returns (bytes32) {
        require(_exists(tokenId), "RenaissRegistry: Nonexistent token.");
        return bytes32(tokenId);
    }

    /**
     * @dev get the Proof of Integrity of a particular token as a string.
     * Requirement:
     *      - the token must exist.
     */
    function getTokenProofOfIntegrityAsHexString(uint256 tokenId) public view returns (string memory) {
        require(_exists(tokenId), "RenaissRegistry: Nonexistent token.");
        return _tokenIdToProofOfIntegrityAsHexString(tokenId);
    }

    /* ================================================ URI HELPERS ================================================ */

    /**
     * @dev Update {tokenBaseUri}. See {MutableTokenURIUpgradeable._updateTokenBaseUri}.
     */
    function updateTokenBaseUri(string memory newURI) public onlyAdmin {
        _updateTokenBaseUri(newURI);
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override(ERC721Upgradeable) returns (string memory) {
        require(_exists(tokenId), "RenaissRegistry: Nonexistent token.");
        return string(
            abi.encodePacked(tokenBaseUri, "/", _tokenIdToProofOfIntegrityAsHexString(tokenId), "/metadata.json")
        );
    }

    /* ============================================ ROYALTY MANAGEMENT ============================================ */

    /**
     * @dev See {IERC2981Upgradeable-royaltyInfo}.
     */
    function royaltyInfo(uint256 tokenId, uint256 salePrice)
        public
        view
        virtual
        override
        returns (address receiver, uint256 amount)
    {
        RoyaltyInfo storage _royaltyInfo = _tokenRoyaltyInfo[tokenId];
        address royaltyReceiver = _royaltyInfo.receiver;
        uint96 royaltyFraction = _royaltyInfo.royaltyFraction;

        uint256 royaltyAmount = (salePrice * royaltyFraction) / _feeDenominator();
        return (royaltyReceiver, royaltyAmount);
    }

    /**
     * @dev The denominator with which to interpret the fee set in {_setTokenRoyalty} and {_setDefaultRoyalty} as a
     * fraction of the sale price. Defaults to 10000 so fees are expressed in basis points.
     */
    function _feeDenominator() internal pure virtual returns (uint96) {
        return 10000;
    }

    /**
     * @dev Sets the royalty information for a specific token id, overriding the global default.
     */
    function _setTokenRoyalty(uint256 tokenId, address _owner) internal virtual {
        require(_owner != address(0), "RenaissRegistry: Invalid token royalty owner");
        require(_exists(tokenId), "RenaissRegistry: Nonexistent token.");

        address splitter =
            RoyaltyPaymentSplitterFactory(royaltyPaymentSplitterFactory).createPaymentSplitter(tokenId, _owner);
        // not created. no need to update royalty info
        if (splitter == address(0)) {
            return;
        }
        _tokenRoyaltyInfo[tokenId] = RoyaltyInfo(splitter, _defaultRoyaltyFeeBps);
        emit TokenRoyaltyUpdated(tokenId, splitter, _defaultRoyaltyFeeBps);
    }

    function setTokenRoyalty(uint256 tokenId, address _owner) public onlyAdmin {
        _setTokenRoyalty(tokenId, _owner);
    }

    /**
     * @dev Set the Renaissance treasury address. Only admin can call this.
     */
    function setTreasury(address _treasury) public onlyAdmin {
        require(_treasury != address(0), "RenaissRegistry: Invalid treasury address");
        treasury = _treasury;
    }

    function setOwnerShares(uint96 _ownerShares) public onlyAdmin {
        RoyaltyPaymentSplitterFactory(royaltyPaymentSplitterFactory).setOwnerShares(_ownerShares);
    }

    /* ============================================ PAUSABILITY HELPERS ============================================ */

    /**
     * @dev Pauses all token transfers. See {PausableUpgradeable-_pause}.
     *
     * - Requirement: the caller must be the admin
     */
    function pause() public virtual onlyAdmin {
        _pause();
    }

    /**
     * @dev Unpauses all token transfers. See {PausableUpgradeable-_unpause}.
     *
     * - Requirement: the caller must be the admin
     */
    function unpause() public virtual onlyAdmin {
        _unpause();
    }

    /* ================================ {ITokenRegistryUpgradeable} IMPLEMENTATION ================================ */

    /**
     * @dev See {ITokenRegistryUpgradeable-mintToken}.
     * @notice we assume the 1st owner of the token will have the royalties.
     */
    function mintToken(address to, bytes32 proofOfIntegrity)
        external
        override(ITokenRegistryUpgradeable)
        onlyMinter
        whenNotPaused
        returns (uint256)
    {
        uint256 tokenId = uint256(proofOfIntegrity);
        require(!_exists(tokenId), "RenaissRegistry: Token already exists.");
        // Set token royalty to the payment splitter
        _safeMint(to, tokenId);
        _setTokenRoyalty(tokenId, to);
        return tokenId;
    }

    /**
     * @dev See {ITokenRegistryUpgradeable-mintTokenBatch}.
     * @return the number of tokens successfully minted that way.
     * - Requirement: {receivers} and {proofsOfIntegrity} must have the same size.
     */
    function mintTokenBatch(address[] calldata receivers, bytes32[] calldata proofsOfIntegrity)
        external
        override(ITokenRegistryUpgradeable)
        onlyMinter
        whenNotPaused
        returns (uint256)
    {
        require(
            receivers.length == proofsOfIntegrity.length,
            "RenaissRegistry: Input Error - the length of input arrays do not match."
        );
        uint256 successes = 0;
        for (uint256 ii = 0; ii < receivers.length; ii++) {
            uint256 tokenId = uint256(proofsOfIntegrity[ii]);
            if (!_exists(tokenId)) {
                _safeMint(receivers[ii], tokenId);
                successes += 1;
            }
        }
        return successes;
    }

    /**
     * @dev See {ITokenRegistryUpgradeable-mintToken}.
     * @notice we assume the 1st owner of the token will have the royalties.
     */
    function mintToken(address to, bytes32 proofOfIntegrity, address royaltyReceiver)
        external
        override(ITokenRegistryUpgradeable)
        onlyMinter
        whenNotPaused
        returns (uint256)
    {
        uint256 tokenId = uint256(proofOfIntegrity);
        require(!_exists(tokenId), "RenaissRegistry: Token already exists.");
        // Set token royalty to the payment splitter
        _safeMint(to, tokenId);
        _setTokenRoyalty(tokenId, royaltyReceiver);
        return tokenId;
    }

    /**
     * @dev See {ITokenRegistryUpgradeable-mintTokenBatch}.
     * @return the number of tokens successfully minted that way.
     * - Requirement: {receivers} and {proofsOfIntegrity} must have the same size.
     */
    function mintTokenBatch(
        address[] calldata receivers,
        bytes32[] calldata proofsOfIntegrity,
        address[] calldata royaltyReceivers
    ) external override(ITokenRegistryUpgradeable) onlyMinter whenNotPaused returns (uint256) {
        require(
            receivers.length == proofsOfIntegrity.length,
            "RenaissRegistry: Input Error - the length of input arrays do not match."
        );
        uint256 successes = 0;
        for (uint256 ii = 0; ii < receivers.length; ii++) {
            uint256 tokenId = uint256(proofsOfIntegrity[ii]);
            if (!_exists(tokenId)) {
                _safeMint(receivers[ii], tokenId);
                _setTokenRoyalty(tokenId, royaltyReceivers[ii]);
                successes += 1;
            }
        }
        return successes;
    }

    /**
     * @dev See {ITokenRegistryUpgradeable-burnToken}.
     */
    function burnToken(bytes32 proofOfIntegrity) external override onlyBurner whenNotPaused returns (bool) {
        uint256 tokenId = uint256(proofOfIntegrity);
        require(ERC721Upgradeable.ownerOf(tokenId) == _msgSender(), "RenaissRegistry: Caller does not own the token.");
        _burn(tokenId);
        return true;
    }

    /**
     * @dev See {ITokenRegistryUpgradeable-burnTokenBatch}.
     * @return the number of tokens successfully burned that way.
     */
    function burnTokenBatch(bytes32[] calldata proofsOfIntegrity)
        external
        override
        onlyBurner
        whenNotPaused
        returns (uint256)
    {
        uint256 successes = 0;
        for (uint256 ii = 0; ii < proofsOfIntegrity.length; ii++) {
            uint256 tokenId = uint256(proofsOfIntegrity[ii]);
            if (_exists(tokenId) && ERC721Upgradeable.ownerOf(tokenId) == _msgSender()) {
                _burn(tokenId);
                successes += 1;
            }
        }
        return successes;
    }

    /* =============================== TOKEN_MODERATOR_ROLE ROLE-SPECIFIC FUNCTIONS =============================== */

    /**
     * @dev Moderator function to replace a faulty token with a new, fixed one.
     * Use cases:
     *  - The {fingerprint} or the original token was faulty, resulting in a fix that changes its {proofOfIntegrity}
     */
    function replaceFaultyToken(bytes32 faultyProofOfIntegrity, bytes32 newProofOfIntegrity)
        external
        onlyTokenModerator
        whenNotPaused
    {
        uint256 faultyTokenId = uint256(faultyProofOfIntegrity);
        uint256 newTokenId = uint256(newProofOfIntegrity);
        require(_exists(faultyTokenId), "RenaissRegistry: The faulty token does not exist.");
        require(!_exists(newTokenId), "RenaissRegistry: The new token requested already exists.");
        address tokenOwner = ERC721Upgradeable.ownerOf(faultyTokenId);
        _burn(faultyTokenId);
        _safeMint(tokenOwner, newTokenId);
        emit ReplacedFaultyToken(_msgSender(), tokenOwner, faultyProofOfIntegrity, newProofOfIntegrity);
    }
}
