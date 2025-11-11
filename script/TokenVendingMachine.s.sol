// script/DeployTokenVendingMachine.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {TokenVendingMachine} from "../src/TokenVendingMachine.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DeploymentManager} from "./DeploymentManager.s.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract DeployScript is Script, DeploymentManager {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        // Get network name from environment variable (e.g., bnb_testnet)
        string memory network = vm.envOr("NETWORK", string("testnet"));
        address deployer = vm.addr(deployerPrivateKey);

        // Load configurations from JSON using the network name

        Deployment memory deployment = loadDeployment(network);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy TokenVendingMachine implementation
        TokenVendingMachine vendingMachineImplementation = new TokenVendingMachine();

        console.log("TokenVendingMachine implementation deployed to:", address(vendingMachineImplementation));

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(TokenVendingMachine.initialize.selector);

        // Deploy ERC1967 proxy with UUPS implementation
        ERC1967Proxy proxy = new ERC1967Proxy(address(vendingMachineImplementation), initData);

        TokenVendingMachine vendingMachine = TokenVendingMachine(address(proxy));
        vendingMachine.hasRole(vendingMachine.DEFAULT_ADMIN_ROLE(), deployer);

        // Update deployment information
        deployment.tokenVendingMachineProxy = address(vendingMachine);
        deployment.tokenVendingMachineImplementation = address(vendingMachineImplementation);
        deployment.timestamp = block.timestamp;

        saveDeployment(network, deployment);
        printDeploymentSummary(network, deployment);

        vm.stopBroadcast();
    }
}
