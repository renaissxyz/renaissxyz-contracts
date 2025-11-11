// script/DeployOrderBook.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import {Script, console} from "forge-std/Script.sol";
import {Orderbook} from "../src/Orderbook.sol";
import {DeploymentManager} from "./DeploymentManager.s.sol";
import {Permit2Transfer, EIP4494Permit, Bid, Ask, Trade} from "../src/Orderbook.sol";
import {RenaissRegistry} from "../src/RenaissRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAllowanceTransfer} from "../src/interface/permit2/IAllowanceTransfer.sol";
import {console} from "forge-std/console.sol";

contract DeployScript is Script, DeploymentManager {
    uint256 signerPk = vm.envUint("PRIVATE_KEY");
    address signer = vm.addr(signerPk);
    // Get network name from environment variable (e.g., bnb_testnet)
    string network = vm.envOr("NETWORK", string("testnet"));

    Deployment deployment = loadDeployment(network);
    Orderbook orderbook = Orderbook(deployment.orderbookProxy);
    RenaissRegistry registry = RenaissRegistry(deployment.registryProxy);

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Get network name from environment variable (e.g., bnb_testnet)
        string memory network = vm.envOr("NETWORK", string("testnet"));
        NetworkConfig memory networkConfig = loadNetworkConfig(network);
        // Load configurations from JSON using the network name

        OrderBookConfig memory orderbookConfig = loadOrderBookConfig(network);
        Deployment memory deployment = loadDeployment(network);

        require(deployment.registryProxy != address(0), "Registry must be deployed first");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy OrderBook implementation using config values
        string memory name = "Renaiss OrderBook";
        string memory version = "1";
        Orderbook orderbookImplementation = new Orderbook();

        console.log("OrderBook implementation deployed to:", address(orderbookImplementation));

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            Orderbook.initialize.selector,
            deployment.registryProxy, // Registry address from deployment
            name,
            version,
            networkConfig.usdc, // USDC address from network config
            orderbookConfig.tradeFeeRecipient // Trade fee recipient from orderbook config
        );

        // Deploy ERC1967 proxy with UUPS implementation
        ERC1967Proxy proxy = new ERC1967Proxy(address(orderbookImplementation), initData);

        Orderbook orderbook = Orderbook(address(proxy));

        console.log("OrderBook proxy deployed to:", address(proxy));
        console.log("verifying registry: ", address(orderbook.registryERC721()));

        console.log("verifying usdc: ", address(orderbook.usdc()));
        console.log("verifying tradeFeeRecipient: ", address(orderbook.tradeFeeRecipient()));

        // Update deployment information
        deployment.orderbookProxy = address(orderbook);
        deployment.orderbookImplementation = address(orderbookImplementation);
        deployment.timestamp = block.timestamp;

        saveDeployment(network, deployment);
        printDeploymentSummary(network, deployment);

        vm.stopBroadcast();
    }

    
}
