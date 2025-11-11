// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "forge-std/Test.sol";
import "../src/RoyaltyPaymentSplitter.sol";
import "../src/RoyaltyPaymentSplitterFactory.sol";
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

contract RoyaltyPaymentSplitterFactoryTest is Test {
    RoyaltyPaymentSplitterFactory public factory;
    MockTokenRegistry public registry;
    MockERC20 public token1;
    MockERC20 public token2;

    address public tokenOwner1 = makeAddr("tokenOwner1");
    address public tokenOwner2 = makeAddr("tokenOwner2");
    address public treasury = makeAddr("treasury");
    address public user = makeAddr("user");

    uint96 public constant OWNER_SHARES = 8000; // 80%
    uint96 public constant TOTAL_SHARES = 10000; // 100%
    uint96 public constant TREASURY_SHARES = 2000; // 20%

    event PaymentSplitterCreated(uint256 indexed tokenId, address indexed splitter, address indexed tokenOwner);

    function setUp() public {
        // Deploy mock registry
        registry = new MockTokenRegistry(treasury);

        // Deploy factory and sign in the registry
        factory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);
        vm.prank(address(registry));
        factory.registryContractSigningIn();

        // Deploy mock ERC20 tokens
        token1 = new MockERC20("Test Token 1", "TEST1");
        token2 = new MockERC20("Test Token 2", "TEST2");

        // Fund accounts
        vm.deal(user, 10 ether);
        token1.mint(user, 1000 * 10 ** 18);
        token2.mint(user, 1000 * 10 ** 18);
    }

    function testFactoryInitialization() public {
        assertEq(factory.ownerShares(), OWNER_SHARES);
        assertEq(factory.TOTAL_SHARES(), TOTAL_SHARES);
        assertEq(factory.registryContract(), address(registry));
        assertNotEq(factory.implementation(), address(0));
    }

    function testCreatePaymentSplitter() public {
        uint256 tokenId = 1;

        address splitterAddress = factory.createPaymentSplitter(tokenId, tokenOwner1);

        // Set the royalty receiver in the mock registry
        registry.setTokenRoyaltyReceiver(tokenId, splitterAddress);

        assertTrue(splitterAddress != address(0));
        assertTrue(factory.paymentSplitterCreated(tokenId));

        // Verify the splitter is properly initialized
        RoyaltyPaymentSplitter splitter = RoyaltyPaymentSplitter(payable(splitterAddress));
        assertEq(splitter.tokenOwner(), tokenOwner1);
        assertEq(splitter.registryContract(), address(registry));
        assertEq(splitter.factory(), address(factory));
        assertEq(splitter.ownerShares(), OWNER_SHARES);
        assertEq(splitter.totalShares(), TOTAL_SHARES);
    }

    function testPredictPaymentSplitterAddress() public {
        uint256 tokenId = 1;

        // Predict address before creation
        address predictedAddress = factory.predictPaymentSplitterAddress(tokenId);

        // Create splitter
        address actualAddress = factory.createPaymentSplitter(tokenId, tokenOwner1);

        // Verify addresses match
        assertEq(predictedAddress, actualAddress);
    }

    function testCreatePaymentSplitterWithZeroOwnerShares() public {
        // Deploy new factory with 0 owner shares
        RoyaltyPaymentSplitterFactory zeroSharesFactory = new RoyaltyPaymentSplitterFactory(0);
        vm.prank(address(registry));
        zeroSharesFactory.registryContractSigningIn();

        uint256 tokenId = 1;
        address splitterAddress = zeroSharesFactory.createPaymentSplitter(tokenId, tokenOwner1);

        // Should return address(0) when owner shares are 0
        assertEq(splitterAddress, address(0));
        assertFalse(zeroSharesFactory.paymentSplitterCreated(tokenId));
    }

    function testCannotCreatePaymentSplitterWithInvalidOwner() public {
        uint256 tokenId = 1;

        vm.expectRevert("Factory: Invalid token owner");
        factory.createPaymentSplitter(tokenId, address(0));
    }

    function testBatchCollectTreasuryPayments() public {
        uint256[] memory tokenIds = new uint256[](3);
        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokenIds[2] = 3;

        // Create splitters and fund them
        address splitter1 = factory.createPaymentSplitter(tokenIds[0], tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenIds[1], tokenOwner2);
        address splitter3 = factory.createPaymentSplitter(tokenIds[2], tokenOwner1);

        // Set royalty receivers in the mock registry
        registry.setTokenRoyaltyReceiver(tokenIds[0], splitter1);
        registry.setTokenRoyaltyReceiver(tokenIds[1], splitter2);
        registry.setTokenRoyaltyReceiver(tokenIds[2], splitter3);

        // Fund splitters with ETH
        vm.deal(splitter1, 1 ether);
        vm.deal(splitter2, 2 ether);
        vm.deal(splitter3, 0.5 ether);

        uint256 treasuryBalanceBefore = treasury.balance;

        // Batch collect treasury payments
        factory.batchCollectTreasuryPayments(tokenIds);

        // Calculate expected treasury payments
        uint256 expectedTreasury1 = (1 ether * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasury2 = (2 ether * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasury3 = (0.5 ether * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 totalExpected = expectedTreasury1 + expectedTreasury2 + expectedTreasury3;

        assertEq(treasury.balance, treasuryBalanceBefore + totalExpected);
    }

    function testBatchCollectTreasuryTokenPayments() public {
        uint256[] memory tokenIds = new uint256[](2);
        address[] memory tokens = new address[](2);
        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokens[0] = address(token1);
        tokens[1] = address(token2);

        // Create splitters
        address splitter1 = factory.createPaymentSplitter(tokenIds[0], tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenIds[1], tokenOwner2);

        // Set royalty receivers in the mock registry
        registry.setTokenRoyaltyReceiver(tokenIds[0], splitter1);
        registry.setTokenRoyaltyReceiver(tokenIds[1], splitter2);

        // Fund splitters with tokens
        uint256 amount1 = 100 * 10 ** 18;
        uint256 amount2 = 200 * 10 ** 18;

        vm.prank(user);
        token1.transfer(splitter1, amount1);
        vm.prank(user);
        token2.transfer(splitter2, amount2);

        uint256 treasuryToken1BalanceBefore = token1.balanceOf(treasury);
        uint256 treasuryToken2BalanceBefore = token2.balanceOf(treasury);

        // Batch collect treasury token payments
        factory.batchCollectTreasuryTokenPayments(tokenIds, tokens);

        // Calculate expected treasury payments
        uint256 expectedTreasuryToken1 = (amount1 * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasuryToken2 = (amount2 * TREASURY_SHARES) / TOTAL_SHARES;

        assertEq(token1.balanceOf(treasury), treasuryToken1BalanceBefore + expectedTreasuryToken1);
        assertEq(token2.balanceOf(treasury), treasuryToken2BalanceBefore + expectedTreasuryToken2);
    }

    function testBatchCollectTreasuryTokenPaymentsMismatchedArrays() public {
        uint256[] memory tokenIds = new uint256[](2);
        address[] memory tokens = new address[](1); // Mismatched length

        vm.expectRevert("Factory: Input arrays must have the same length");
        factory.batchCollectTreasuryTokenPayments(tokenIds, tokens);
    }

    function testGetReleasableTreasuryAmounts() public {
        uint256[] memory tokenIds = new uint256[](3);
        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokenIds[2] = 3;

        // Create splitters and fund them
        address splitter1 = factory.createPaymentSplitter(tokenIds[0], tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenIds[1], tokenOwner2);
        address splitter3 = factory.createPaymentSplitter(tokenIds[2], tokenOwner1);

        // Set royalty receivers in the mock registry
        registry.setTokenRoyaltyReceiver(tokenIds[0], splitter1);
        registry.setTokenRoyaltyReceiver(tokenIds[1], splitter2);
        registry.setTokenRoyaltyReceiver(tokenIds[2], splitter3);

        // Fund splitters with different amounts
        vm.deal(splitter1, 1 ether);
        vm.deal(splitter2, 2 ether);
        vm.deal(splitter3, 0.5 ether);

        (uint256[] memory amounts, uint256 totalReleasable) = factory.getReleasableTreasuryAmounts(tokenIds);

        // Calculate expected amounts
        uint256 expectedAmount1 = (1 ether * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedAmount2 = (2 ether * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedAmount3 = (0.5 ether * TREASURY_SHARES) / TOTAL_SHARES;
        uint256 expectedTotal = expectedAmount1 + expectedAmount2 + expectedAmount3;

        assertEq(amounts.length, 3);
        assertEq(amounts[0], expectedAmount1);
        assertEq(amounts[1], expectedAmount2);
        assertEq(amounts[2], expectedAmount3);
        assertEq(totalReleasable, expectedTotal);
    }

    function testGetReleasableTreasuryAmountsWithNonExistentSplitters() public view {
        uint256[] memory tokenIds = new uint256[](2);
        tokenIds[0] = 999; // Non-existent
        tokenIds[1] = 1000; // Non-existent

        (uint256[] memory amounts, uint256 totalReleasable) = factory.getReleasableTreasuryAmounts(tokenIds);

        assertEq(amounts.length, 2);
        assertEq(amounts[0], 0);
        assertEq(amounts[1], 0);
        assertEq(totalReleasable, 0);
    }

    function testSetOwnerShares() public {
        uint96 newOwnerShares = 7500; // 75%

        // Only registry contract can call this
        vm.prank(address(registry));
        factory.setOwnerShares(newOwnerShares);

        assertEq(factory.ownerShares(), newOwnerShares);
    }

    function testCannotSetOwnerSharesFromNonRegistry() public {
        uint96 newOwnerShares = 7500;

        vm.prank(user);
        vm.expectRevert("Factory: Only registry contract can call this function");
        factory.setOwnerShares(newOwnerShares);
    }

    function testFactoryConstructorValidation() public {
        // Test valid owner shares (0 is now allowed)
        RoyaltyPaymentSplitterFactory zeroFactory = new RoyaltyPaymentSplitterFactory(0);
        assertEq(zeroFactory.ownerShares(), 0);

        // Test invalid owner shares (> TOTAL_SHARES)
        vm.expectRevert("Factory: Invalid owner shares");
        new RoyaltyPaymentSplitterFactory(10001);
    }

    function testBatchOperationsWithEmptyArrays() public {
        uint256[] memory emptyTokenIds = new uint256[](0);
        address[] memory emptyTokens = new address[](0);

        // Should not revert with empty arrays
        factory.batchCollectTreasuryPayments(emptyTokenIds);
        factory.batchCollectTreasuryTokenPayments(emptyTokenIds, emptyTokens);

        (uint256[] memory amounts, uint256 totalReleasable) = factory.getReleasableTreasuryAmounts(emptyTokenIds);
        assertEq(amounts.length, 0);
        assertEq(totalReleasable, 0);
    }

    function testBatchOperationsWithUnfundedSplitters() public {
        uint256[] memory tokenIds = new uint256[](2);
        address[] memory tokens = new address[](2);
        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokens[0] = address(token1);
        tokens[1] = address(token2);

        // Create splitters but don't fund them
        address splitter1 = factory.createPaymentSplitter(tokenIds[0], tokenOwner1);
        address splitter2 = factory.createPaymentSplitter(tokenIds[1], tokenOwner2);

        // Set royalty receivers in the mock registry
        registry.setTokenRoyaltyReceiver(tokenIds[0], splitter1);
        registry.setTokenRoyaltyReceiver(tokenIds[1], splitter2);

        // Batch operations should not revert even if no payments are due
        factory.batchCollectTreasuryPayments(tokenIds);
        factory.batchCollectTreasuryTokenPayments(tokenIds, tokens);

        (uint256[] memory amounts, uint256 totalReleasable) = factory.getReleasableTreasuryAmounts(tokenIds);
        assertEq(amounts[0], 0);
        assertEq(amounts[1], 0);
        assertEq(totalReleasable, 0);
    }

    function testDeterministicAddresses() public {
        uint256 tokenId1 = 1;
        uint256 tokenId2 = 2;

        // Predict addresses
        address predicted1 = factory.predictPaymentSplitterAddress(tokenId1);
        address predicted2 = factory.predictPaymentSplitterAddress(tokenId2);

        // Addresses should be different for different token IDs
        assertTrue(predicted1 != predicted2);

        // Create splitters
        address actual1 = factory.createPaymentSplitter(tokenId1, tokenOwner1);
        address actual2 = factory.createPaymentSplitter(tokenId2, tokenOwner2);

        // Verify predicted addresses match actual addresses
        assertEq(predicted1, actual1);
        assertEq(predicted2, actual2);
    }

    function testFuzzCreatePaymentSplitter(uint256 tokenId, address tokenOwner_) public {
        // Ensure tokenOwner is not zero address
        vm.assume(tokenOwner_ != address(0));

        address predictedAddress = factory.predictPaymentSplitterAddress(tokenId);
        address actualAddress = factory.createPaymentSplitter(tokenId, tokenOwner_);

        assertEq(predictedAddress, actualAddress);
        assertTrue(factory.paymentSplitterCreated(tokenId));

        RoyaltyPaymentSplitter splitter = RoyaltyPaymentSplitter(payable(actualAddress));
        assertEq(splitter.tokenOwner(), tokenOwner_);
    }
}
