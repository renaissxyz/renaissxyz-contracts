// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "forge-std/Test.sol";
import "../src/RoyaltyPaymentSplitter.sol";
import "../src/RoyaltyPaymentSplitterFactory.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock contracts for testing
contract MockTokenRegistry {
    address private _treasury;

    constructor(address treasury_) {
        _treasury = treasury_;
    }

    function treasury() external view returns (address) {
        return _treasury;
    }

    function setTreasury(address newTreasury) external {
        _treasury = newTreasury;
    }
}

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract RoyaltyPaymentSplitterTest is Test {
    RoyaltyPaymentSplitter public implementation;
    RoyaltyPaymentSplitter public splitter;
    RoyaltyPaymentSplitterFactory public factory;
    MockTokenRegistry public registry;
    MockERC20 public token;

    address public tokenOwner = makeAddr("tokenOwner");
    address public treasury = makeAddr("treasury");
    address public user = makeAddr("user");

    uint96 public constant OWNER_SHARES = 8000; // 80%
    uint96 public constant TOTAL_SHARES = 10000; // 100%
    uint96 public constant TREASURY_SHARES = 2000; // 20%
    uint256 public constant TOKEN_ID = 1;

    event PaymentReceived(address from, uint256 amount);
    event PaymentReleased(address to, uint256 amount);
    event ERC20PaymentReleased(IERC20 indexed token, address to, uint256 amount);

    function setUp() public {
        // Deploy mock registry
        registry = new MockTokenRegistry(treasury);

        // Deploy factory and sign in the registry
        factory = new RoyaltyPaymentSplitterFactory(OWNER_SHARES);
        vm.prank(address(registry));
        factory.registryContractSigningIn();

        // Create a payment splitter instance
        address splitterAddress = factory.createPaymentSplitter(TOKEN_ID, tokenOwner);
        splitter = RoyaltyPaymentSplitter(payable(splitterAddress));

        // Deploy mock ERC20 token
        token = new MockERC20("Test Token", "TEST");

        // Fund accounts
        vm.deal(user, 10 ether);
        token.mint(user, 1000 * 10 ** 18);
    }

    function testInitialization() public view {
        assertEq(splitter.tokenOwner(), tokenOwner);
        assertEq(splitter.registryContract(), address(registry)); // Should match the registry we passed to factory
        assertEq(splitter.factory(), address(factory));
        assertEq(splitter.ownerShares(), OWNER_SHARES);
        assertEq(splitter.totalShares(), TOTAL_SHARES);
    }

    function testReceiveEther() public {
        uint256 amount = 1 ether;

        vm.expectEmit(true, false, false, true);
        emit PaymentReceived(user, amount);

        vm.prank(user);
        (bool success,) = address(splitter).call{value: amount}("");
        assertTrue(success);

        assertEq(address(splitter).balance, amount);
    }

    function testOwnerReleasableCalculation() public {
        uint256 amount = 1 ether;

        // Send ETH to splitter
        vm.prank(user);
        (bool success,) = address(splitter).call{value: amount}("");
        assertTrue(success);

        // Check owner releasable amount (80%)
        uint256 expectedOwnerAmount = (amount * OWNER_SHARES) / TOTAL_SHARES;
        assertEq(splitter.ownerReleasable(), expectedOwnerAmount);

        // Check treasury releasable amount (20%)
        uint256 expectedTreasuryAmount = (amount * TREASURY_SHARES) / TOTAL_SHARES;
        assertEq(splitter.treasuryReleasable(), expectedTreasuryAmount);
    }

    function testReleaseToOwner() public {
        uint256 amount = 1 ether;
        uint256 expectedOwnerPayment = (amount * OWNER_SHARES) / TOTAL_SHARES;

        // Send ETH to splitter
        vm.prank(user);
        (bool success,) = address(splitter).call{value: amount}("");
        assertTrue(success);

        uint256 ownerBalanceBefore = tokenOwner.balance;

        vm.expectEmit(true, false, false, true);
        emit PaymentReleased(tokenOwner, expectedOwnerPayment);

        splitter.releaseToOwner();

        assertEq(tokenOwner.balance, ownerBalanceBefore + expectedOwnerPayment);
        assertEq(splitter.ownerReleased(), expectedOwnerPayment);
        assertEq(splitter.totalReleased(), expectedOwnerPayment);
        assertEq(splitter.ownerReleasable(), 0);
    }

    function testReleaseToTreasury() public {
        uint256 amount = 1 ether;
        uint256 expectedTreasuryPayment = (amount * TREASURY_SHARES) / TOTAL_SHARES;

        // Send ETH to splitter
        vm.prank(user);
        (bool success,) = address(splitter).call{value: amount}("");
        assertTrue(success);

        uint256 treasuryBalanceBefore = treasury.balance;

        vm.expectEmit(true, false, false, true);
        emit PaymentReleased(treasury, expectedTreasuryPayment);

        splitter.releaseToTreasury();

        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryPayment);
        assertEq(splitter.treasuryReleased(), expectedTreasuryPayment);
        assertEq(splitter.totalReleased(), expectedTreasuryPayment);
        assertEq(splitter.treasuryReleasable(), 0);
    }

    function testReleaseToOwnerERC20() public {
        uint256 amount = 100 * 10 ** 18;
        uint256 expectedOwnerPayment = (amount * OWNER_SHARES) / TOTAL_SHARES;

        // Send tokens to splitter
        vm.prank(user);
        token.transfer(address(splitter), amount);

        uint256 ownerBalanceBefore = token.balanceOf(tokenOwner);

        vm.expectEmit(true, true, false, true);
        emit ERC20PaymentReleased(token, tokenOwner, expectedOwnerPayment);

        splitter.releaseToOwner(token);

        assertEq(token.balanceOf(tokenOwner), ownerBalanceBefore + expectedOwnerPayment);
        assertEq(splitter.ownerReleased(token), expectedOwnerPayment);
        assertEq(splitter.totalReleased(token), expectedOwnerPayment);
        assertEq(splitter.ownerReleasable(token), 0);
    }

    function testReleaseToTreasuryERC20() public {
        uint256 amount = 100 * 10 ** 18;
        uint256 expectedTreasuryPayment = (amount * TREASURY_SHARES) / TOTAL_SHARES;

        // Send tokens to splitter
        vm.prank(user);
        token.transfer(address(splitter), amount);

        uint256 treasuryBalanceBefore = token.balanceOf(treasury);

        vm.expectEmit(true, true, false, true);
        emit ERC20PaymentReleased(token, treasury, expectedTreasuryPayment);

        splitter.releaseToTreasury(token);

        assertEq(token.balanceOf(treasury), treasuryBalanceBefore + expectedTreasuryPayment);
        assertEq(splitter.treasuryReleased(token), expectedTreasuryPayment);
        assertEq(splitter.totalReleased(token), expectedTreasuryPayment);
        assertEq(splitter.treasuryReleasable(token), 0);
    }

    function testCannotReleaseWhenNoPaymentDue() public {
        vm.expectRevert("PaymentSplitter: owner is not due payment");
        splitter.releaseToOwner();

        vm.expectRevert("PaymentSplitter: owner is not due payment");
        splitter.releaseToTreasury();

        vm.expectRevert("PaymentSplitter: account is not due payment");
        splitter.releaseToOwner(token);

        vm.expectRevert("PaymentSplitter: account is not due payment");
        splitter.releaseToTreasury(token);
    }

    function testMultiplePaymentsAndReleases() public {
        uint256 firstPayment = 1 ether;
        uint256 secondPayment = 2 ether;
        uint256 totalPayment = firstPayment + secondPayment;

        // First payment
        vm.prank(user);
        (bool success,) = address(splitter).call{value: firstPayment}("");
        assertTrue(success);

        // Release to owner
        splitter.releaseToOwner();
        uint256 firstOwnerPayment = (firstPayment * OWNER_SHARES) / TOTAL_SHARES;
        assertEq(splitter.ownerReleased(), firstOwnerPayment);

        // Second payment
        vm.prank(user);
        (success,) = address(splitter).call{value: secondPayment}("");
        assertTrue(success);

        // Release to treasury
        splitter.releaseToTreasury();
        uint256 totalTreasuryPayment = (totalPayment * TREASURY_SHARES) / TOTAL_SHARES;
        assertEq(splitter.treasuryReleased(), totalTreasuryPayment);

        // Release remaining to owner
        splitter.releaseToOwner();
        uint256 totalOwnerPayment = (totalPayment * OWNER_SHARES) / TOTAL_SHARES;
        assertEq(splitter.ownerReleased(), totalOwnerPayment);
    }

    function testFuzzReleaseAmounts(uint256 amount) public {
        // Bound the amount to reasonable values that avoid rounding to zero
        amount = bound(amount, TOTAL_SHARES, 1000 ether);

        // Send ETH to splitter
        vm.deal(address(this), amount);
        (bool success,) = address(splitter).call{value: amount}("");
        assertTrue(success);

        // Calculate expected amounts
        uint256 expectedOwnerAmount = (amount * OWNER_SHARES) / TOTAL_SHARES;
        uint256 expectedTreasuryAmount = (amount * TREASURY_SHARES) / TOTAL_SHARES;

        // Verify releasable amounts
        assertEq(splitter.ownerReleasable(), expectedOwnerAmount);
        assertEq(splitter.treasuryReleasable(), expectedTreasuryAmount);

        // Release and verify
        uint256 ownerBalanceBefore = tokenOwner.balance;
        uint256 treasuryBalanceBefore = treasury.balance;

        splitter.releaseToOwner();
        splitter.releaseToTreasury();

        assertEq(tokenOwner.balance, ownerBalanceBefore + expectedOwnerAmount);
        assertEq(treasury.balance, treasuryBalanceBefore + expectedTreasuryAmount);

        // Verify total released equals total received (minus rounding)
        uint256 totalReleased = expectedOwnerAmount + expectedTreasuryAmount;
        assertTrue(totalReleased <= amount);
        assertTrue(amount - totalReleased < TOTAL_SHARES); // Rounding error should be less than TOTAL_SHARES
    }

    function testCannotInitializeTwice() public {
        vm.expectRevert("Initializable: contract is already initialized");
        splitter.initialize(tokenOwner, address(registry), OWNER_SHARES, TOTAL_SHARES);
    }

    function testInitializeWithInvalidParameters() public {
        RoyaltyPaymentSplitter newSplitter = new RoyaltyPaymentSplitter();

        vm.expectRevert("RoyaltyPaymentSplitter: Invalid token owner");
        newSplitter.initialize(address(0), address(registry), OWNER_SHARES, TOTAL_SHARES);

        vm.expectRevert("RoyaltyPaymentSplitter: Invalid registry");
        newSplitter.initialize(tokenOwner, address(0), OWNER_SHARES, TOTAL_SHARES);
    }
}
