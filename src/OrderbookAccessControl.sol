// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./interface/IOrderbookAccessControl.sol";
import "solady/utils/EfficientHashLib.sol";

abstract contract OrderbookAccessControl is
    Initializable,
    AccessControlEnumerableUpgradeable,
    IOrderbookAccessControl
{
    function __OrderbookAccessControl_init() internal onlyInitializing {
        __AccessControlEnumerable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function grantRole(bytes32, address) public pure override(AccessControlUpgradeable, IAccessControlUpgradeable) {
        revert("Orderbook: A role can only be granted using the corresponding specialized function");
    }

    function revokeRole(bytes32, address) public pure override(AccessControlUpgradeable, IAccessControlUpgradeable) {
        revert("Orderbook: A role can only be revoked using the corresponding specialized function");
    }

    function listRoleMembers(bytes32 role) public view override returns (address[] memory) {
        uint256 memberCount = getRoleMemberCount(role);
        address[] memory members = new address[](memberCount);
        for (uint256 i = 0; i < memberCount; i++) {
            members[i] = getRoleMember(role, i);
        }
        return members;
    }

    /* ================================================ ADMIN ROLE ================================================ */

    /**
     * @dev Modifier that checks that the sender has the {DEFAULT_ADMIN_ROLE} role.
     */
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Orderbook: Caller is missing role ADMIN.");
        _;
    }

    /**
     * @dev transfer the {DEFAULT_ADMIN_ROLE} role to another wallet.
     *
     * note: because {grantRole} and {revokeRole} are not accessible externally, this function ensures that there
     * can only be a single admin for this contract at any time.
     */
    function transferAdmin(address _to) public override onlyAdmin {
        super.grantRole(DEFAULT_ADMIN_ROLE, _to);
        super.revokeRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**
     * @dev returns the address of the admin of this registry.
     */
    function admin() public view override returns (address) {
        return getRoleMember(DEFAULT_ADMIN_ROLE, 0);
    }

    /* ================================================ TRUSTED Trader ROLE ================================================ */

    /**
     * @dev the trusted trader role that allows addresses to act as trusted traders.
     */
    function TRUSTED_TRADER_ROLE() public pure override returns (bytes32) {
        return keccak256("TRUSTED_TRADER_ROLE");
    }

    /**
     * @dev Modifier that checks that the sender has the {TRUSTED_TRADER_ROLE} role.
     */
    modifier onlyTrustedTrader() {
        require(hasRole(TRUSTED_TRADER_ROLE(), _msgSender()), "Orderbook: Caller is missing role TRUSTED_TRADER_ROLE.");
        _;
    }

    /**
     * @dev grant the TRUSTED_TRADER_ROLE role.
     */
    function grantTrustedTraderRole(address account) public override onlyAdmin {
        super.grantRole(TRUSTED_TRADER_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_TRADER_ROLE role.
     */
    function revokeTrustedTraderRole(address account) public override onlyAdmin {
        super.revokeRole(TRUSTED_TRADER_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_TRADER_ROLE} role.
     */
    function hasTrustedTraderRole(address account) public view override returns (bool) {
        return hasRole(TRUSTED_TRADER_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_TRADER_ROLE} role.
     */
    function listTrustedTraderRoleMembers() public view override returns (address[] memory) {
        return listRoleMembers(TRUSTED_TRADER_ROLE());
    }

    /* ================================================ TRUSTED CALLER ROLE ================================================ */

    /**
     * @dev the trusted caller role that allows addresses to act as trusted callers.
     */
    function TRUSTED_CALLER_ROLE() public pure override returns (bytes32) {
        return keccak256("TRUSTED_CALLER_ROLE");
    }

    /**
     * @dev Modifier that checks that the sender has the {TRUSTED_CALLER_ROLE} role.
     */
    modifier onlyTrustedCaller() {
        require(hasRole(TRUSTED_CALLER_ROLE(), _msgSender()), "Orderbook: Caller is missing role TRUSTED_CALLER_ROLE.");
        _;
    }

    /**
     * @dev grant the TRUSTED_CALLER_ROLE role.
     */
    function grantTrustedCallerRole(address account) public override onlyAdmin {
        super.grantRole(TRUSTED_CALLER_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_CALLER_ROLE role.
     */
    function revokeTrustedCallerRole(address account) public override onlyAdmin {
        super.revokeRole(TRUSTED_CALLER_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_CALLER_ROLE} role.
     */
    function hasTrustedCallerRole(address account) public view override returns (bool) {
        return hasRole(TRUSTED_CALLER_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_CALLER_ROLE} role.
     */
    function listTrustedCallerRoleMembers() public view override returns (address[] memory) {
        return listRoleMembers(TRUSTED_CALLER_ROLE());
    }

    /* ================================================ TRUSTED CONCTRACT ROLE ================================================ */

    /**
     * @dev the trusted caller role that allows addresses to act as trusted callers.
     */
    function TRUSTED_CONTRACT_ROLE() public pure override returns (bytes32) {
        return EfficientHashLib.hash(bytes32("TRUSTED_CONTRACT_ROLE"));
    }

    /**
     * @dev grant the TRUSTED_CONTRACT_ROLE role.
     */
    function grantTrustedContractRole(address account) public override onlyAdmin {
        super.grantRole(TRUSTED_CONTRACT_ROLE(), account);
    }

    /**
     * @dev revoke the TRUSTED_CONTRACT_ROLE role.
     */
    function revokeTrustedContractRole(address account) public override onlyAdmin {
        super.revokeRole(TRUSTED_CONTRACT_ROLE(), account);
    }

    /**
     * @dev check if an address has the {TRUSTED_CONTRACT_ROLE} role.
     */
    function hasTrustedContractRole(address account) public view override returns (bool) {
        return hasRole(TRUSTED_CONTRACT_ROLE(), account);
    }

    /**
     * @dev list the addresses that have the {TRUSTED_CONTRACT_ROLE} role.
     */
    function listTrustedContractRoleMembers() public view override returns (address[] memory) {
        return listRoleMembers(TRUSTED_CONTRACT_ROLE());
    }
}
