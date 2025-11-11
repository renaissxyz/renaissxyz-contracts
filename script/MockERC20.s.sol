// script/MockERC20.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {MockERC20} from "../test/mock/MockERC20.sol";
import {DeploymentManager} from "./DeploymentManager.s.sol";

contract DeployScript is Script, DeploymentManager {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory network = vm.envOr("NETWORK", string("testnet"));
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying MockERC20 to network:", network);
        console.log("Deployer address:", deployer);

        // Load existing deployment
        Deployment memory deployment = loadDeployment(network);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy MockERC20 with permit functionality
        MockERC20 mockUSDC = new MockERC20(
            "Mock USDC", // name
            "MUSDC-18", // symbol
            18,
            1000000 * 10 ** 18
        );

        console.log("MockERC20 (USDC) deployed to:", address(mockUSDC));
        console.log("Initial supply:", mockUSDC.totalSupply());
        console.log("Deployer balance:", mockUSDC.balanceOf(deployer));

        // Update deployment information
        deployment.mockUSDC = address(mockUSDC);
        deployment.timestamp = block.timestamp;

        // Save deployment
        saveDeployment(network, deployment);
        printMockERC20Summary(network, deployment, mockUSDC);

        vm.stopBroadcast();
    }

    function mintTokens() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory network = vm.envOr("NETWORK", string("testnet"));
        address deployer = vm.addr(deployerPrivateKey);

        // Load deployment
        Deployment memory deployment = loadDeployment(network);

        if (deployment.mockUSDC == address(0)) {
            revert("MockERC20 not deployed yet. Run the main deployment first.");
        }

        vm.startBroadcast(deployerPrivateKey);

        MockERC20 mockUSDC = MockERC20(deployment.mockUSDC);

        // Mint additional tokens to deployer (for testing)
        uint256 additionalAmount = 1000000 * 10 ** 6; // 1M USDC
        mockUSDC.mint(deployer, additionalAmount);

        console.log("Minted additional tokens:", additionalAmount);
        console.log("New deployer balance:", mockUSDC.balanceOf(deployer));

        vm.stopBroadcast();
    }

    function mintToAddress(address recipient, uint256 amount) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory network = vm.envOr("NETWORK", string("testnet"));

        // Load deployment
        Deployment memory deployment = loadDeployment(network);

        if (deployment.mockUSDC == address(0)) {
            revert("MockERC20 not deployed yet. Run the main deployment first.");
        }

        vm.startBroadcast(deployerPrivateKey);

        MockERC20 mockUSDC = MockERC20(deployment.mockUSDC);
        mockUSDC.mint(recipient, amount);

        console.log("Minted to address:", recipient);
        console.log("Amount:", amount);
        console.log("New recipient balance:", mockUSDC.balanceOf(recipient));

        vm.stopBroadcast();
    }

    function approveToPermit2() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory network = vm.envOr("NETWORK", string("testnet"));
        NetworkConfig memory networkConfig = loadNetworkConfig(network);
        address deployer = vm.addr(deployerPrivateKey);

        // Load deployment
        Deployment memory deployment = loadDeployment(network);

        if (deployment.mockUSDC == address(0)) {
            revert("MockERC20 not deployed yet. Run the main deployment first.");
        }

        if (MockERC20(deployment.mockUSDC).allowance(deployer, networkConfig.permit2) == type(uint256).max) {
            console.log("MockERC20 already approved to Permit2");
            return;
        }

        vm.startBroadcast(deployerPrivateKey);

        MockERC20 mockUSDC = MockERC20(deployment.mockUSDC);
        mockUSDC.approve(networkConfig.permit2, type(uint256).max);

        if (mockUSDC.allowance(deployer, networkConfig.permit2) == type(uint256).max) {
            console.log("Approved to Permit2:", networkConfig.permit2);
        } else {
            revert("MockERC20 not approved to Permit2. Run the approveToPermit2 function first.");
        }

        vm.stopBroadcast();
    }

    function printMockERC20Summary(string memory network, Deployment memory deployment, MockERC20 mockUSDC)
        public
        view
    {
        console.log("\n=== MockERC20 Deployment Summary ===");
        console.log("Network:", network);
        console.log("MockERC20 Address:", deployment.mockUSDC);
        console.log("Name:", mockUSDC.name());
        console.log("Symbol:", mockUSDC.symbol());
        console.log("Decimals:", mockUSDC.decimals());
        console.log("Total Supply:", mockUSDC.totalSupply());
        console.log("Deployment Timestamp:", deployment.timestamp);
        console.log("=====================================\n");
    }
}
