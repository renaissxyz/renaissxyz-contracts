// script/DeployRoyaltyPaymentSplitterFactory.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {RoyaltyPaymentSplitterFactory} from "../src/RoyaltyPaymentSplitterFactory.sol";
import {DeploymentManager} from "./DeploymentManager.s.sol";

contract DeployScript is Script, DeploymentManager {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Get network name from environment variable (e.g., bnb_testnet)
        string memory network = vm.envOr("NETWORK", string("testnet"));

        // Load registry configuration from JSON using the network name
        RegistryConfig memory config = loadRegistryConfig(network);

        // Use owner shares from config or environment variable
        uint96 ownerShares = uint96(config.ownerShares);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy RoyaltyPaymentSplitterFactory
        RoyaltyPaymentSplitterFactory factory = new RoyaltyPaymentSplitterFactory(ownerShares);

        console.log("RoyaltyPaymentSplitterFactory deployed to:", address(factory));
        console.log("Owner shares:", factory.ownerShares(), "/ 10000");
        console.log("Treasury shares:", factory.TOTAL_SHARES() - factory.ownerShares(), "/ 10000");
        console.log("RoyaltyPaymentSplitter Implementation contract:", factory.implementation());

        // Save deployment information
        Deployment memory deployment = loadDeployment(network);
        deployment.royaltyFactory = address(factory);

        saveDeployment(network, deployment);
        printDeploymentSummary(network, deployment);

        vm.stopBroadcast();
    }
}
