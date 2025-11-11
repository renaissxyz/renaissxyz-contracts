// script/DeployRenaissRegistry.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {RenaissRegistry} from "../src/RenaissRegistry.sol";
import {RenaissRegistryV3} from "../src/RenaissRegistryV3.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DeploymentManager} from "./DeploymentManager.s.sol";
import {RoyaltyPaymentSplitterFactory} from "../src/RoyaltyPaymentSplitterFactory.sol";
import {RoyaltyPaymentSplitter} from "../src/RoyaltyPaymentSplitter.sol";
import {Orderbook} from "../src/Orderbook.sol";

contract DeployScript is Script, DeploymentManager {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Get network name from environment variable (e.g., bnb_testnet)
        string memory network = vm.envOr("NETWORK", string("testnet"));

        // Load network configuration from JSON using the network name
        NetworkConfig memory networkConfig = loadNetworkConfig(network);
        RegistryConfig memory registryConfig = loadRegistryConfig(network);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy implementation
        RenaissRegistryV3 implementation = new RenaissRegistryV3();
        console.log("RenaissRegistryV3 implementation deployed to:", address(implementation));

        // Prepare initialization data using config values
        bytes memory initData = abi.encodeWithSelector(
            RenaissRegistryV3.initialize.selector,
            registryConfig.admin, // contractAdmin
            registryConfig.registryURI, // uri from config
            registryConfig.registryName, // tokenName from config
            registryConfig.registrySymbol, // tokenSymbol from config
            registryConfig.treasury // treasury address from config
        );

        // Deploy proxy
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        console.log("RenaissRegistryV3 proxy deployed to:", address(proxy));

        RenaissRegistryV3 registry = RenaissRegistryV3(address(proxy));
        // check admin has role
        bool adminIsSet = registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), registryConfig.admin);
        if (!adminIsSet) {
            revert("Admin role not set");
        } else {
            console.log("Admin role is set");
        }
        // check uri, tokenName, tokenSymbol
        console.log("Registry URI:", registry.tokenBaseUri());
        console.log("Registry name:", registry.name());
        console.log("Registry symbol:", registry.symbol());
        console.log("Registry treasury:", registry.treasury());

        // load the original deployment
        Deployment memory deployment = loadDeployment(network);
        // Save deployment information
        deployment.registryProxy = address(proxy);
        deployment.registryImplementation = address(implementation);
        deployment.timestamp = block.timestamp;
        deployment.network = network;

        saveDeployment(network, deployment);
        printDeploymentSummary(network, deployment);

        vm.stopBroadcast();
    }
}
