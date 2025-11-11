// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

// solhint-disable func-name-mixedcase
interface IOrderbookAccessControl {
    // Admin Role Functions
    function transferAdmin(address account) external;

    function admin() external view returns (address);

    // Access Control Functions
    function TRUSTED_TRADER_ROLE() external pure returns (bytes32);

    function grantTrustedTraderRole(address account) external;

    function revokeTrustedTraderRole(address account) external;

    function hasTrustedTraderRole(address account) external view returns (bool);

    function listTrustedTraderRoleMembers() external view returns (address[] memory);

    // Trusted Caller Role Functions
    function TRUSTED_CALLER_ROLE() external pure returns (bytes32);

    function grantTrustedCallerRole(address account) external;

    function revokeTrustedCallerRole(address account) external;

    function hasTrustedCallerRole(address account) external view returns (bool);

    function listTrustedCallerRoleMembers() external view returns (address[] memory);
    // Trusted Contract Role Functions
    function TRUSTED_CONTRACT_ROLE() external pure returns (bytes32);

    function grantTrustedContractRole(address account) external;

    function revokeTrustedContractRole(address account) external;

    function hasTrustedContractRole(address account) external view returns (bool);

    function listTrustedContractRoleMembers() external view returns (address[] memory);

    // Generic Role Helper
    function listRoleMembers(bytes32 role) external view returns (address[] memory);
}
