// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "forge-std/Test.sol";
import "../src/RoyaltyPaymentSplitter.sol";
import "../src/RoyaltyPaymentSplitterFactory.sol";
import "../src/RenaissRegistryV3.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock contracts for testing
contract MockTokenRegistry {
    address private _treasury;
    mapping(uint256 => address) private _tokenRoyaltyReceivers;

    constructor(address treasury_) {
        _treasury = treasury_;
    }

    function treasury() external view returns (address) {
        return _treasury;
    }

    function setTreasury(address newTreasury) external {
        _treasury = newTreasury;
    }

    function setTokenRoyaltyReceiver(uint256 tokenId, address receiver) external {
        _tokenRoyaltyReceivers[tokenId] = receiver;
    }

    function royaltyInfo(uint256 tokenId, uint256 /* salePrice */) external view returns (address, uint256) {
        address receiver = _tokenRoyaltyReceivers[tokenId];
        return (receiver, 0);
    }
}

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract RoyaltyPaymentSplitterIntegrationTest is Test {
    RoyaltyPaymentSplitterFactory public factory;
    MockTokenRegistry public mockRegistry;
    RenaissRegistryV3 public realRegistry;
    ERC1967Proxy public registryProxy;
    MockERC20 public usdc;
    MockERC20 public weth;

    address public tokenOwner1 = makeAddr("tokenOwner1");
    address public tokenOwner2 = makeAddr("tokenOwner2");
    address public tokenOwner3 = makeAddr("tokenOwner3");
    address public treasury = makeAddr("treasury");
    address public admin = makeAddr("admin");
    address public user = makeAddr("user");
    address public royaltyReceiver = makeAddr("royaltyReceiver");

    uint96 public constant OWNER_SHARES = 8000; // 80%
    uint96 public constant TOTAL_SHARES = 10000; // 100%
    uint96 public constant TREASURY_SHARES = 2000; // 20%

    function setUp() public {
        // Deploy mock registry for compatibility tests
        mockRegistry = new MockTokenRegistry(treasury);

        // Deploy real RenaissRegistry for integration tests
        RenaissRegistryV3 implementation = new RenaissRegistryV3();
        bytes memory initData = abi.encodeWithSelector(
            RenaissRegistryV3.initialize.selector,
            admin, // contractAdmin
            "https://api.renaiss.com/registry", // uri
            "Renaiss Registry Test", // tokenName
            "RENAISS-TEST", // tokenSymbol
            treasury // treasury address
        );
        registryProxy = new ERC1967Proxy(address(implementation), initData);
        realRegistry = RenaissRegistryV3(address(registryProxy));

        // Grant MINTER_ROLE to admin so we can mint tokens in tests
        vm.prank(admin);
        realRegistry.grantMinterRole(admin);

        // Deploy factory for mock registry tests (old behavior)
        factory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);
        vm.prank(address(mockRegistry));
        factory.registryContractSigningIn();

        // Deploy mock ERC20 tokens
        usdc = new MockERC20("USD Coin", "USDC");
        weth = new MockERC20("Wrapped Ether", "WETH");

        // Fund accounts
        vm.deal(user, 100 ether);
        vm.deal(royaltyReceiver, 50 ether);
        usdc.mint(user, 10000 * 10 ** 6); // 10,000 USDC
        usdc.mint(royaltyReceiver, 5000 * 10 ** 6); // 5,000 USDC
        weth.mint(user, 100 * 10 ** 18); // 100 WETH
    }

    function testCompleteRoyaltyDistributionWorkflow() public {
        uint256 tokenId1 = 1;
        uint256 tokenId2 = 2;

        // Create payment splitters for two tokens
        address splitter1 = factory.createPaymentSplitter(tokenId1, tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenId2, tokenOwner2);

        // Set royalty receivers in the mock registry
        mockRegistry.setTokenRoyaltyReceiver(tokenId1, splitter1);
        mockRegistry.setTokenRoyaltyReceiver(tokenId2, splitter2);

        // Simulate royalty payments to splitters
        uint256 royalty1 = 5 ether;
        uint256 royalty2 = 3 ether;

        vm.deal(splitter1, royalty1);
        vm.deal(splitter2, royalty2);

        // Get initial balances
        uint256 owner1BalanceBefore = tokenOwner1.balance;
        uint256 owner2BalanceBefore = tokenOwner2.balance;
        uint256 treasuryBalanceBefore = treasury.balance;

        // Release payments to owners
        RoyaltyPaymentSplitter(payable(splitter1)).releaseToOwner();
        RoyaltyPaymentSplitter(payable(splitter2)).releaseToOwner();

        // Use factory to batch collect treasury payments
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = tokenId1;
        tokenIds[1] = tokenId2;
        factory.batchCollectTreasuryPayments(tokenIds);

        // Verify final balances
        uint256 expectedOwner1Payment = (royalty1 * OWNER_SHARES) / TOTAL_SHARES;
        uint256 expectedOwner2Payment = (royalty2 * OWNER_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasuryPayment = ((royalty1 + royalty2) * TREASURY_SHARES) / TOTAL_SHARES;

        assertEq(tokenOwner1.balance, owner1BalanceBefore + expectedOwner1Payment);
        assertEq(tokenOwner2.balance, owner2BalanceBefore + expectedOwner2Payment);
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryPayment);
    }

    function testMultiTokenRoyaltyDistribution() public {
        uint256 tokenId = 1;
        address splitter = factory.createPaymentSplitter(tokenId, tokenOwner1);

        // Send different types of tokens as royalties
        uint256 usdcAmount = 1000 * 10 ** 6; // 1,000 USDC
        uint256 wethAmount = 2 * 10 ** 18; // 2 WETH
        uint256 ethAmount = 1 ether; // 1 ETH

        vm.prank(user);
        usdc.transfer(splitter, usdcAmount);

        vm.prank(user);
        weth.transfer(splitter, wethAmount);

        vm.deal(splitter, ethAmount);

        // Get initial balances
        uint256 owner1UsdcBefore = usdc.balanceOf(tokenOwner1);
        uint256 owner1WethBefore = weth.balanceOf(tokenOwner1);
        uint256 owner1EthBefore = tokenOwner1.balance;

        uint256 treasuryUsdcBefore = usdc.balanceOf(treasury);
        uint256 treasuryWethBefore = weth.balanceOf(treasury);
        uint256 treasuryEthBefore = treasury.balance;

        // Release all payments
        RoyaltyPaymentSplitter splitterContract = RoyaltyPaymentSplitter(payable(splitter));
        splitterContract.releaseToOwner(usdc);
        splitterContract.releaseToOwner(weth);
        splitterContract.releaseToOwner();
        splitterContract.releaseToTreasury(usdc);
        splitterContract.releaseToTreasury(weth);
        splitterContract.releaseToTreasury();

        // Verify distributions
        uint256 expectedOwnerUsdc = (usdcAmount * OWNER_SHARES) / TOTAL_SHARES;
        uint256 expectedOwnerWeth = (wethAmount * OWNER_SHARES) / TOTAL_SHARES;
        uint256 expectedOwnerEth = (ethAmount * OWNER_SHARES) / TOTAL_SHARES;

        uint256 expectedTreasuryUsdc = (usdcAmount * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasuryWeth = (wethAmount * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasuryEth = (ethAmount * TREASURY_SHARES) / TOTAL_SHARES;

        assertEq(usdc.balanceOf(tokenOwner1), owner1UsdcBefore + expectedOwnerUsdc);
        assertEq(weth.balanceOf(tokenOwner1), owner1WethBefore + expectedOwnerWeth);
        assertEq(tokenOwner1.balance, owner1EthBefore + expectedOwnerEth);

        assertEq(usdc.balanceOf(treasury), treasuryUsdcBefore + expectedTreasuryUsdc);
        assertEq(weth.balanceOf(treasury), treasuryWethBefore + expectedTreasuryWeth);
        assertEq(treasury.balance, treasuryEthBefore + expectedTreasuryEth);
    }

    function testBatchOperationsWithMixedTokenTypes() public {
        uint256[] memory tokenIds = new uint256[](3);
        address[] memory tokens = new address[](3);

        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokenIds[2] = 3;
        tokens[0] = address(usdc);
        tokens[1] = address(weth);
        tokens[2] = address(usdc);

        // Create splitters
        address splitter1 = factory.createPaymentSplitter(tokenIds[0], tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenIds[1], tokenOwner2);
        address splitter3 = factory.createPaymentSplitter(tokenIds[2], tokenOwner3);

        // Set royalty receivers in the mock registry
        mockRegistry.setTokenRoyaltyReceiver(tokenIds[0], splitter1);
        mockRegistry.setTokenRoyaltyReceiver(tokenIds[1], splitter2);
        mockRegistry.setTokenRoyaltyReceiver(tokenIds[2], splitter3);

        // Fund splitters with respective tokens
        vm.prank(user);
        usdc.transfer(splitter1, 500 * 10 ** 6);

        vm.prank(user);
        weth.transfer(splitter2, 1 * 10 ** 18);

        vm.prank(user);
        usdc.transfer(splitter3, 300 * 10 ** 6);

        uint256 treasuryUsdcBefore = usdc.balanceOf(treasury);
        uint256 treasuryWethBefore = weth.balanceOf(treasury);

        // Batch collect treasury token payments
        factory.batchCollectTreasuryTokenPayments(tokenIds, tokens);

        // Verify treasury received correct amounts
        uint256 expectedUsdcFromSplitter1 = (500 * 10 ** 6 * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedWethFromSplitter2 = (1 * 10 ** 18 * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedUsdcFromSplitter3 = (300 * 10 ** 6 * TREASURY_SHARES) / TOTAL_SHARES;

        assertEq(usdc.balanceOf(treasury), treasuryUsdcBefore + expectedUsdcFromSplitter1 + expectedUsdcFromSplitter3);
        assertEq(weth.balanceOf(treasury), treasuryWethBefore + expectedWethFromSplitter2);
    }

    function testTreasuryAddressChange() public {
        uint256 tokenId = 1;
        address splitter = factory.createPaymentSplitter(tokenId, tokenOwner1);

        // Fund splitter
        vm.deal(splitter, 2 ether);

        // Change treasury address
        address newTreasury = makeAddr("newTreasury");
        mockRegistry.setTreasury(newTreasury);

        uint256 oldTreasuryBalanceBefore = treasury.balance;
        uint256 newTreasuryBalanceBefore = newTreasury.balance;

        // Release treasury payment
        RoyaltyPaymentSplitter(payable(splitter)).releaseToTreasury();

        uint256 expectedTreasuryPayment = (2 ether * TREASURY_SHARES) / TOTAL_SHARES;

        // Verify payment went to new treasury
        assertEq(treasury.balance, oldTreasuryBalanceBefore); // Old treasury unchanged
        assertEq(newTreasury.balance, newTreasuryBalanceBefore + expectedTreasuryPayment);
    }

    function testFactoryOwnerSharesChange() public {
        // Deploy new factory with different shares
        uint96 newOwnerShares = 9000; // 90%

        RoyaltyPaymentSplitterFactory newFactory = new RoyaltyPaymentSplitterFactory(newOwnerShares);
        vm.prank(address(mockRegistry));
        newFactory.registryContractSigningIn();

        uint256 tokenId = 1;
        address splitter = newFactory.createPaymentSplitter(tokenId, tokenOwner1);

        // Fund splitter
        vm.deal(splitter, 1 ether);

        uint256 ownerBalanceBefore = tokenOwner1.balance;
        uint256 treasuryBalanceBefore = treasury.balance;

        // Release payments
        RoyaltyPaymentSplitter splitterContract = RoyaltyPaymentSplitter(payable(splitter));
        splitterContract.releaseToOwner();
        splitterContract.releaseToTreasury();

        // Verify new distribution ratios
        uint256 expectedOwnerPayment = (1 ether * newOwnerShares) / TOTAL_SHARES;
        uint256 expectedTreasuryPayment = (1 ether * (TOTAL_SHARES - newOwnerShares)) / TOTAL_SHARES;

        assertEq(tokenOwner1.balance, ownerBalanceBefore + expectedOwnerPayment);
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryPayment);
    }

    function testComplexScenarioWithPartialReleases() public {
        uint256 tokenId = 1;
        address splitter = factory.createPaymentSplitter(tokenId, tokenOwner1);

        // First royalty payment
        vm.deal(splitter, 1 ether);

        // Release to owner only
        RoyaltyPaymentSplitter splitterContract = RoyaltyPaymentSplitter(payable(splitter));
        splitterContract.releaseToOwner();

        // Second royalty payment
        vm.deal(splitter, address(splitter).balance + 2 ether);

        // Third royalty payment
        vm.deal(splitter, address(splitter).balance + 0.5 ether);

        uint256 treasuryBalanceBefore = treasury.balance;

        // Now release all treasury payments
        splitterContract.releaseToTreasury();

        // Treasury should receive share of all payments (3.5 ETH total)
        uint256 expectedTreasuryPayment = (3.5 ether * TREASURY_SHARES) / TOTAL_SHARES;
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryPayment);

        // Release remaining owner payment
        uint256 ownerBalanceBefore = tokenOwner1.balance;
        splitterContract.releaseToOwner();

        uint256 expectedAdditionalOwnerPayment = (2.5 ether * OWNER_SHARES) / TOTAL_SHARES;
        assertEq(tokenOwner1.balance, ownerBalanceBefore + expectedAdditionalOwnerPayment);
    }

    function testGasOptimizationBatchOperations() public {
        uint256 numTokens = 10;
        uint256[] memory tokenIds = new uint256[](numTokens);

        // Create multiple splitters
        for (uint256 i = 0; i < numTokens; i++) {
            tokenIds[i] = i + 1;
            address splitter = factory.createPaymentSplitter(tokenIds[i], tokenOwner1);
            mockRegistry.setTokenRoyaltyReceiver(tokenIds[i], splitter);
            vm.deal(splitter, 0.1 ether);
        }

        // Measure gas for batch collection
        uint256 gasBefore = gasleft();
        factory.batchCollectTreasuryPayments(tokenIds);
        uint256 gasUsed = gasBefore - gasleft();

        // Verify all payments were collected
        uint256 expectedTotalTreasuryPayment = (1 ether * TREASURY_SHARES) / TOTAL_SHARES; // 10 * 0.1 ether

        // Gas usage should be reasonable for batch operation
        assertLt(gasUsed, 1000000); // Should use less than 1M gas for 10 splitters

        (uint256[] memory amounts, uint256 totalReleasable) = factory.getReleasableTreasuryAmounts(tokenIds);
        assertEq(totalReleasable, 0); // All should be released
    }

    function testErrorHandlingInBatchOperations() public {
        uint256[] memory tokenIds = new uint256[](3);
        tokenIds[0] = 1; // Will have funds
        tokenIds[1] = 999; // Non-existent splitter
        tokenIds[2] = 2; // Will have funds

        // Create only two splitters
        address splitter1 = factory.createPaymentSplitter(tokenIds[0], tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenIds[2], tokenOwner2);

        // Set royalty receivers in the mock registry
        mockRegistry.setTokenRoyaltyReceiver(tokenIds[0], splitter1);
        mockRegistry.setTokenRoyaltyReceiver(tokenIds[2], splitter2);

        vm.deal(splitter1, 1 ether);
        vm.deal(splitter2, 1 ether);

        uint256 treasuryBalanceBefore = treasury.balance;

        // Batch operation should not revert even with non-existent splitter
        factory.batchCollectTreasuryPayments(tokenIds);

        // Should have collected from the two existing splitters
        uint256 expectedTreasuryPayment = (2 ether * TREASURY_SHARES) / TOTAL_SHARES;
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryPayment);
    }

    // ========================= REAL REGISTRY INTEGRATION TESTS =========================

    function testRealRegistryRoyaltyInfoIntegration() public {
        // Deploy a new factory connected to the real registry
        RoyaltyPaymentSplitterFactory realFactory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);

        // Set up the factory in the registry and sign in
        vm.prank(admin);
        realRegistry.setRoyaltyPaymentSplitterFactory(address(realFactory));

        // Mint a token (this automatically calls _setTokenRoyalty internally)
        bytes32 proofOfIntegrity = keccak256("test-proof-royalty");
        uint256 tokenId = uint256(proofOfIntegrity);
        vm.prank(admin);
        realRegistry.mintToken(tokenOwner1, proofOfIntegrity);

        // Check that royalty info returns the payment splitter address
        (address receiver, uint256 amount) = realRegistry.royaltyInfo(tokenId, 1000 ether);

        address expectedSplitter = realFactory.predictPaymentSplitterAddress(tokenId);
        uint256 expectedAmount = (1000 ether * 100) / 10000; // 100 bps = 1%

        assertEq(receiver, expectedSplitter);
        assertEq(amount, expectedAmount);
        assertTrue(realFactory.paymentSplitterCreated(tokenId));
    }

    function testMintWithAutomaticRoyaltySetup() public {
        // Deploy a new factory connected to the real registry
        RoyaltyPaymentSplitterFactory realFactory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);

        // Set up the factory in the registry
        vm.prank(admin);
        realRegistry.setRoyaltyPaymentSplitterFactory(address(realFactory));

        // Mint a token (this should automatically set up royalty info)
        bytes32 proofOfIntegrity = keccak256("test-proof");
        uint256 tokenId = uint256(proofOfIntegrity);

        vm.prank(admin);
        uint256 mintedTokenId = realRegistry.mintToken(tokenOwner1, proofOfIntegrity);

        assertEq(mintedTokenId, tokenId);

        // Check that royalty info was automatically set up
        (address receiver, uint256 amount) = realRegistry.royaltyInfo(tokenId, 1000 ether);

        address expectedSplitter = realFactory.predictPaymentSplitterAddress(tokenId);
        uint256 expectedAmount = (1000 ether * 100) / 10000; // 100 bps = 1%

        assertEq(receiver, expectedSplitter);
        assertEq(amount, expectedAmount);
        assertTrue(realFactory.paymentSplitterCreated(tokenId));

        // Verify the token was minted to the correct owner
        assertEq(realRegistry.ownerOf(tokenId), tokenOwner1);
    }

    function testRoyaltyPaymentThroughRealRegistry() public {
        // Deploy a new factory connected to the real registry
        RoyaltyPaymentSplitterFactory realFactory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);

        // Set up the factory in the registry
        vm.prank(admin);
        realRegistry.setRoyaltyPaymentSplitterFactory(address(realFactory));

        // Mint a token
        bytes32 proofOfIntegrity = keccak256("test-proof-payment");
        uint256 tokenId = uint256(proofOfIntegrity);

        vm.prank(admin);
        realRegistry.mintToken(tokenOwner1, proofOfIntegrity);

        // Get the splitter address
        (address splitterAddress,) = realRegistry.royaltyInfo(tokenId, 1000 ether);

        // Send royalty payment to the splitter
        uint256 royaltyAmount = 5 ether;
        vm.deal(splitterAddress, royaltyAmount);

        // Get initial balances
        uint256 ownerBalanceBefore = tokenOwner1.balance;
        uint256 treasuryBalanceBefore = treasury.balance;

        // Release payments
        RoyaltyPaymentSplitter splitter = RoyaltyPaymentSplitter(payable(splitterAddress));
        splitter.releaseToOwner();
        splitter.releaseToTreasury();

        // Verify distributions
        uint256 expectedOwnerPayment = (royaltyAmount * OWNER_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasuryPayment = (royaltyAmount * TREASURY_SHARES) / TOTAL_SHARES;

        assertEq(tokenOwner1.balance, ownerBalanceBefore + expectedOwnerPayment);
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryPayment);
    }

    function testBatchOperationsWithRealRegistry() public {
        // Deploy a new factory connected to the real registry
        RoyaltyPaymentSplitterFactory realFactory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);

        // Set up the factory in the registry
        vm.prank(admin);
        realRegistry.setRoyaltyPaymentSplitterFactory(address(realFactory));

        // Mint multiple tokens
        uint256[] memory tokenIds = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 proof = keccak256(abi.encodePacked("test-proof-", i));
            tokenIds[i] = uint256(proof);

            vm.prank(admin);
            realRegistry.mintToken(tokenOwner1, proof);

            // Fund each splitter
            (address splitterAddress,) = realRegistry.royaltyInfo(tokenIds[i], 1000 ether);
            vm.deal(splitterAddress, 1 ether);
        }

        uint256 treasuryBalanceBefore = treasury.balance;

        // Use batch collection
        realFactory.batchCollectTreasuryPayments(tokenIds);

        // Verify treasury received payments from all splitters
        uint256 expectedTotalTreasuryPayment = (3 ether * TREASURY_SHARES) / TOTAL_SHARES;
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTotalTreasuryPayment);
    }

    function testRegistryContractSigningInSecurity() public {
        // Deploy a new factory
        RoyaltyPaymentSplitterFactory newFactory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);

        // Verify registry is not set initially
        assertEq(newFactory.registryContract(), address(0));

        // First, let the real registry call it
        vm.prank(admin);
        realRegistry.setRoyaltyPaymentSplitterFactory(address(newFactory));

        // Verify the registry is now set
        assertEq(newFactory.registryContract(), address(realRegistry));

        // Now trying to call it again should fail
        vm.prank(address(realRegistry));
        vm.expectRevert("Factory: Registry contract already set");
        newFactory.registryContractSigningIn();

        // Other addresses should also not be able to call it
        vm.prank(user);
        vm.expectRevert("Factory: Registry contract already set");
        newFactory.registryContractSigningIn();
    }

    function testZeroOwnerSharesWithRealRegistry() public {
        // Deploy a factory with zero owner shares
        RoyaltyPaymentSplitterFactory zeroShareFactory = new RoyaltyPaymentSplitterFactory(0);

        // Set up the factory in the registry
        vm.prank(admin);
        realRegistry.setRoyaltyPaymentSplitterFactory(address(zeroShareFactory));

        // Mint a token with zero shares factory - should not create a splitter
        bytes32 proofOfIntegrity = keccak256("test-proof-zero-shares");
        uint256 tokenId = uint256(proofOfIntegrity);
        vm.prank(admin);
        realRegistry.mintToken(tokenOwner1, proofOfIntegrity);

        // Check that no splitter was created
        assertFalse(zeroShareFactory.paymentSplitterCreated(tokenId));

        // Royalty info should return zero address and zero amount
        (address receiver,) = realRegistry.royaltyInfo(tokenId, 1000 ether);
        assertEq(receiver, address(0));
    }
}
