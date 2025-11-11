// script/DeploymentManager.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

/**
 * @title DeploymentManager
 * @dev Utility contract for managing deployments across networks
 */
contract DeploymentManager is Script {
    using stdJson for string;

    struct NetworkConfig {
        string name;
        uint256 chainId;
        address usdc;
        address permit2;
    }

    struct RegistryConfig {
        address treasury;
        uint256 ownerShares;
        string registryName;
        string registrySymbol;
        string registryURI;
        address admin;
    }

    struct OrderBookConfig {
        address tradeFeeRecipient;
    }

    struct Deployment {
        uint256 chainId;
        string network;
        uint256 timestamp;
        address registryProxy;
        address registryImplementation;
        address royaltyFactory;
        address orderbookProxy;
        address orderbookImplementation;
        address tokenVendingMachineProxy;
        address tokenVendingMachineImplementation;
        address mockUSDC;
    }

    /**
     * @dev Load network configuration from JSON file
     */
    function loadNetworkConfig(string memory network) public view returns (NetworkConfig memory config) {
        string memory configPath = string(abi.encodePacked("script/config/", network, ".json"));

        try vm.readFile(configPath) returns (string memory data) {
            config.name = data.readString(".network.name");
            config.chainId = data.readUint(".network.chainId");
            config.usdc = data.readAddress(".network.usdc");
            // Handle optional permit2 field
            if (data.keyExists(".network.permit2")) {
                config.permit2 = data.readAddress(".network.permit2");
            } else {
                config.permit2 = address(0);
            }

            console.log("Loaded network config for:", network);
        } catch {
            revert(string(abi.encodePacked("Config file not found: ", configPath)));
        }
    }

    /**
     * @dev Load registry configuration from JSON file
     */
    function loadRegistryConfig(string memory network) public view returns (RegistryConfig memory config) {
        string memory configPath = string(abi.encodePacked("script/config/", network, ".json"));

        try vm.readFile(configPath) returns (string memory data) {
            config.treasury = data.readAddress(".registry.treasury");
            config.ownerShares = data.readUint(".registry.ownerShares");
            config.registryName = data.readString(".registry.registryName");
            config.registrySymbol = data.readString(".registry.registrySymbol");
            config.registryURI = data.readString(".registry.registryURI");
            config.admin = data.readAddress(".registry.admin");

            console.log("Loaded registry config for:", network);
        } catch {
            revert(string(abi.encodePacked("Config file not found: ", configPath)));
        }
    }
    
    
    
    /**
     * @dev Load orderbook configuration from JSON file
     */
    function loadOrderBookConfig(string memory network) public view returns (OrderBookConfig memory config) {
        string memory configPath = string(abi.encodePacked("script/config/", network, ".json"));

        try vm.readFile(configPath) returns (string memory data) {
            config.tradeFeeRecipient = data.readAddress(".orderbook.tradeFeeRecipient");

            console.log("Loaded orderbook config for:", network);
        } catch {
            revert(string(abi.encodePacked("Config file not found: ", configPath)));
        }
    }

    /**
     * @dev Save deployment to JSON file (only when --broadcast flag is used)
     */
    function saveDeployment(string memory network, Deployment memory deployment) public {
        // Only save if not in dry run mode
        if (keccak256(bytes(vm.envOr("DRY_RUN", string("")))) == keccak256(bytes("true"))) {
            console.log("DRY_RUN mode - skipping deployment save");
            return;
        }
        string memory json = "deployment";
        json.serialize("chainId", block.chainid);
        json.serialize("network", deployment.network);
        json.serialize("timestamp", deployment.timestamp);
        json.serialize("registryImplementation", deployment.registryImplementation);
        json.serialize("registryProxy", deployment.registryProxy);
        json.serialize("royaltyFactory", deployment.royaltyFactory);
        json.serialize("orderbookProxy", deployment.orderbookProxy);
        json.serialize("orderbookImplementation", deployment.orderbookImplementation);
        json.serialize("mockUSDC", deployment.mockUSDC);
        json.serialize("tokenVendingMachineProxy", deployment.tokenVendingMachineProxy);
        string memory finalJson = json.serialize("tokenVendingMachineImplementation", deployment.tokenVendingMachineImplementation);
        
        
        // Ensure deployments directory exists
        try vm.readDir("deployments") {}
        catch {
            // Directory doesn't exist, create it
            try vm.writeFile("deployments/.gitkeep", "") {}
            catch {
                // If that fails, try creating with a different approach
                vm.createDir("deployments", true);
            }
        }

        string memory deploymentPath = string(abi.encodePacked("deployments/", network, ".json"));
        vm.writeJson(finalJson, deploymentPath);

        console.log("Deployment saved to:", deploymentPath);
    }

    /**
     * @dev Load existing deployment from JSON file
     */
    function loadDeployment(string memory network) public view returns (Deployment memory deployment) {
        string memory deploymentPath = string(abi.encodePacked("deployments/", network, ".json"));

        try vm.readFile(deploymentPath) returns (string memory data) {
            // Check if each key exists before reading to handle empty deployment files
            if (data.keyExists(".mockUSDC")) {
                deployment.mockUSDC = data.readAddress(".mockUSDC");
            }
            if (data.keyExists(".chainId")) {
                deployment.chainId = data.readUint(".chainId");
            }
            if (data.keyExists(".network")) {
                deployment.network = data.readString(".network");
            }
            if (data.keyExists(".timestamp")) {
                deployment.timestamp = data.readUint(".timestamp");
            }
            if (data.keyExists(".registryImplementation")) {
                deployment.registryImplementation = data.readAddress(".registryImplementation");
            }
            if (data.keyExists(".registryProxy")) {
                deployment.registryProxy = data.readAddress(".registryProxy");
            }
            if (data.keyExists(".royaltyFactory")) {
                deployment.royaltyFactory = data.readAddress(".royaltyFactory");
            }
            if (data.keyExists(".orderbookProxy")) {
                deployment.orderbookProxy = data.readAddress(".orderbookProxy");
            }
            if (data.keyExists(".orderbookImplementation")) {
                deployment.orderbookImplementation = data.readAddress(".orderbookImplementation");
            }
            if (data.keyExists(".tokenVendingMachineProxy")) {
                deployment.tokenVendingMachineProxy = data.readAddress(".tokenVendingMachineProxy");
            }
            if (data.keyExists(".tokenVendingMachineImplementation")) {
                deployment.tokenVendingMachineImplementation = data.readAddress(".tokenVendingMachineImplementation");
            }
            
            console.log("Loaded deployment for network:", network);
        } catch {
            console.log("No existing deployment found for network:", network);
            // Return empty deployment
        }
    }

    
    /**
     * @dev Get registry address for current network
     */
    function getRegistryAddress() public view returns (address) {
        string memory network = vm.envOr("NETWORK", string("sepolia"));
        Deployment memory deployment = loadDeployment(network);

        require(deployment.registryProxy != address(0), "Registry not deployed");
        return deployment.registryProxy;
    }

    /**
     * @dev Get all deployment addresses for current network
     */
    function getAllAddresses() public view returns (Deployment memory) {
        string memory network = vm.envOr("NETWORK", string("sepolia"));
        return loadDeployment(network);
    }

    /**
     * @dev Print deployment summary
     */
    function printDeploymentSummary(string memory network, Deployment memory deployment) public view {
        console.log("=== DEPLOYMENT SUMMARY ===");
        console.log("Network:", network);
        console.log("Chain ID:", deployment.chainId);
        console.log("");
        console.log("Core Contracts:");
        console.log("  Registry (Implementation):", deployment.registryImplementation);
        console.log("  Registry (Proxy) [MAIN]:", deployment.registryProxy);
        console.log("  RoyaltyPaymentSplitterFactory:", deployment.royaltyFactory);
        console.log("");
        console.log("Marketplace Contracts:");
        if (deployment.orderbookProxy != address(0)) {
            console.log("  OrderBook:", deployment.orderbookProxy);
            console.log("  OrderBook (Implementation):", deployment.orderbookImplementation);
        } else {
            console.log("  OrderBook: Not deployed");
        }
        if (deployment.tokenVendingMachineProxy != address(0)) {
            console.log("  TokenVendingMachine (Implementation):", deployment.tokenVendingMachineImplementation);
            console.log("  TokenVendingMachine:", deployment.tokenVendingMachineProxy);
        } else {
            console.log("  TokenVendingMachine: Not deployed");
        }
        
        console.log("==========================");
    }

    /**
     * @dev Verify all contracts are deployed correctly
     */
    function verifyDeployment(string memory network) public view returns (bool) {
        Deployment memory deployment = loadDeployment(network);

        bool isValid = true;

        if (deployment.registryProxy == address(0)) {
            console.log("Registry not deployed");
            isValid = false;
        }

        if (deployment.royaltyFactory == address(0)) {
            console.log("RoyaltyPaymentSplitterFactory not deployed");
            isValid = false;
        }

        if (isValid) {
            console.log("Core deployment is valid");
        }

        return isValid;
    }
}
