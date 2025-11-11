// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/TokenVendingMachine.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {MockERC20} from "./mock/mockERC20.sol";
import {Permit2Deployer} from "./utils/Permit2Deployer.sol";
import {IEIP712} from "../src/interface/permit2/IEIP712.sol";

contract TokenVendingMachineTest is Test, Permit2Deployer {
    using Strings for uint256;

    TokenVendingMachine public vendingMachine;
    MockERC20 public paymentToken;

    address public admin;
    address public buyer;
    uint256 public buyerPk;
    address public oracle;
    uint256 public oraclePk;
    address public trustedCaller;
    address public buybackAdmin;
    uint256 public buybackAdminPk;

    bytes32 public constant TEST_PACK_ID = keccak256("test_pack_v1");

    // Events
    event CheckoutSuccess(address indexed caller, bytes32 indexed checkoutMessageHash);
    event BuybackSuccess(bytes32 indexed checkoutMessageHash, address token, uint256 indexed amount);

    // Helper struct to avoid stack too deep
    struct PermitFundsData {
        bytes32 checkoutId;
        bytes checkoutMessage;
        bytes oracleSignature;
        bytes buyerCheckoutSignature;
        bytes buyerAuthData;
        bytes buyerAuthSignature;
    }

    function setUp() public {
        admin = makeAddr("admin");
        (buyer, buyerPk) = makeAddrAndKey("buyer");
        (oracle, oraclePk) = makeAddrAndKey("oracle");
        trustedCaller = makeAddr("trustedCaller");
        (buybackAdmin, buybackAdminPk) = makeAddrAndKey("buybackAdmin");

        // Deploy Permit2 using utility function
        deployPermit2();

        vm.startPrank(admin);

        // Deploy payment token
        paymentToken = new MockERC20("USDC", "USDC", 6, 1000000 * 10 ** 6);

        // Deploy vending machine storage
        TokenVendingMachine vendingMachineImpl = new TokenVendingMachine();
        bytes memory vendingInitData = abi.encodeWithSelector(TokenVendingMachine.initialize.selector);
        ERC1967Proxy vendingProxy = new ERC1967Proxy(address(vendingMachineImpl), vendingInitData);
        vendingMachine = TokenVendingMachine(address(vendingProxy));

        // Setup roles
        vendingMachine.addTrustedCheckoutOracle(oracle);
        vendingMachine.addTrustedCaller(trustedCaller);
        vendingMachine.addTrustedBuybackRole(buybackAdmin);

        // Fund buyer and buyback admin
        paymentToken.mint(buyer, 10000 * 10 ** 6);
        paymentToken.mint(buybackAdmin, 10000 * 10 ** 6);

        vm.stopPrank();

        // Buyer approves Permit2 to spend tokens (one-time approval)
        vm.prank(buyer);
        paymentToken.approve(PERMIT2_ADDRESS, type(uint256).max);

        // Buyback admin approves vending machine to pull tokens for refunds
        vm.prank(buybackAdmin);
        paymentToken.approve(address(vendingMachine), type(uint256).max);
    }

    // ============================================
    // Helper Functions
    // ============================================

    function _createCheckoutMessage(bytes32 checkoutId) internal view returns (bytes memory) {
        return abi.encode(checkoutId, block.timestamp + 3600, 1000 * 10 ** 6);
    }

    function _signMessage(bytes memory message, uint256 pk) internal pure returns (bytes memory) {
        bytes32 ethSignedHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", message.length.toString(), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function _createBuyerAuth(bytes memory checkoutMessage) internal view returns (bytes memory) {
        uint256 deadline = block.timestamp + 3600;
        uint256 nonce = uint256(keccak256(abi.encodePacked("vendor_nonce", checkoutMessage, block.timestamp)));

        // Create Permit2 SignatureTransfer signature
        (uint8 permitV, bytes32 permitR, bytes32 permitS) = _signPermit2SignatureTransfer(
            buyerPk, buyer, address(paymentToken), 1000 * 10 ** 6, nonce, deadline
        );

        TokenVendingMachine.BuyerAuthorization memory auth = TokenVendingMachine.BuyerAuthorization({
            checkoutId: keccak256(checkoutMessage),
            permitR: permitR,
            permitS: permitS,
            token: address(paymentToken),
            permitDeadline: uint48(deadline),
            permitV: permitV,
            nonce: nonce,
            amount: 1000 * 10 ** 6
        });
        return abi.encode(auth);
    }

    function _signPermit2SignatureTransfer(
        uint256 privateKey,
        address owner,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (uint8, bytes32, bytes32) {
        bytes32 TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
        bytes32 PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
            "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
        );

        // Hash the TokenPermissions struct
        bytes32 tokenPermissions = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, token, amount));

        // Hash the PermitTransferFrom
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                IEIP712(PERMIT2_ADDRESS).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissions, address(vendingMachine), nonce, deadline)
                )
            )
        );

        return vm.sign(privateKey, msgHash);
    }

    function _preparePermitFundsData(bytes32 checkoutId) internal returns (PermitFundsData memory data) {
        data.checkoutId = checkoutId;
        data.checkoutMessage = _createCheckoutMessage(checkoutId);
        data.oracleSignature = _signMessage(data.checkoutMessage, oraclePk);
        data.buyerCheckoutSignature = _signMessage(data.checkoutMessage, buyerPk);
        data.buyerAuthData = _createBuyerAuth(data.checkoutMessage);
        data.buyerAuthSignature = _signMessage(data.buyerAuthData, buyerPk);
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    // ============================================
    // Merkle Proof Tests
    // ============================================

    function testSetMerkleRoot() public {
        bytes32 merkleRoot = keccak256("merkle_root_hash");

        vm.prank(admin);
        vendingMachine.setMerkleRoot(TEST_PACK_ID, merkleRoot);

        assertEq(vendingMachine.getMerkleRoot(TEST_PACK_ID), merkleRoot);
    }

    function testGetMerkleRoot_NotSet() public {
        bytes32 invalidPackId = keccak256("invalid_pack");

        vm.expectRevert("TokenVendingMachine: Merkle root not set for this pack");
        vendingMachine.getMerkleRoot(invalidPackId);
    }

    function testVerifyMerkleProof_ValidProof() public {
        // Create a simple merkle tree with 4 leaves
        bytes32 leaf1 = keccak256(abi.encodePacked("token1"));
        bytes32 leaf2 = keccak256(abi.encodePacked("token2"));
        bytes32 leaf3 = keccak256(abi.encodePacked("token3"));
        bytes32 leaf4 = keccak256(abi.encodePacked("token4"));

        // Build merkle tree
        bytes32 node1 = _hashPair(leaf1, leaf2);
        bytes32 node2 = _hashPair(leaf3, leaf4);
        bytes32 root = _hashPair(node1, node2);

        // Set merkle root
        vm.prank(admin);
        vendingMachine.setMerkleRoot(TEST_PACK_ID, root);

        // Create proof for leaf1
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaf2;
        proof[1] = node2;

        // Verify proof
        assertTrue(vendingMachine.verifyMerkleProof(TEST_PACK_ID, proof, leaf1));
    }

    function testVerifyMerkleProof_InvalidProof() public {
        // Create merkle tree
        bytes32 leaf1 = keccak256(abi.encodePacked("token1"));
        bytes32 leaf2 = keccak256(abi.encodePacked("token2"));
        bytes32 root = _hashPair(leaf1, leaf2);

        // Set merkle root
        vm.prank(admin);
        vendingMachine.setMerkleRoot(TEST_PACK_ID, root);

        // Create invalid proof
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = keccak256("wrong_proof");

        // Verify proof fails
        assertFalse(vendingMachine.verifyMerkleProof(TEST_PACK_ID, invalidProof, leaf1));
    }

    function testVerifyMerkleProof_PackNotSet() public {
        bytes32 invalidPackId = keccak256("invalid_pack");
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("proof");
        bytes32 leaf = keccak256(abi.encodePacked("leaf"));

        vm.expectRevert("TokenVendingMachine: Merkle root not set for this pack");
        vendingMachine.verifyMerkleProof(invalidPackId, proof, leaf);
    }

    function testUpdateMerkleRoot() public {
        bytes32 oldRoot = keccak256("old_root");
        bytes32 newRoot = keccak256("new_root");

        vm.startPrank(admin);

        vendingMachine.setMerkleRoot(TEST_PACK_ID, oldRoot);
        assertEq(vendingMachine.getMerkleRoot(TEST_PACK_ID), oldRoot);

        vendingMachine.setMerkleRoot(TEST_PACK_ID, newRoot);
        assertEq(vendingMachine.getMerkleRoot(TEST_PACK_ID), newRoot);

        vm.stopPrank();
    }

    // ============================================
    // PermitFunds Tests
    // ============================================

    function testPermitFunds_Success() public {
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_1"));

        uint256 buyerBalanceBefore = paymentToken.balanceOf(buyer);
        uint256 contractBalanceBefore = paymentToken.balanceOf(address(vendingMachine));

        // Execute permitFunds (uses permit signature, no need for approval)
        vm.expectEmit(true, true, true, true);
        emit CheckoutSuccess(buyer, keccak256(data.checkoutMessage));

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        // Verify checkout was processed
        assertTrue(vendingMachine.exists(keccak256(data.checkoutMessage)));

        // Verify payment transferred
        assertEq(paymentToken.balanceOf(buyer), buyerBalanceBefore - 1000 * 10 ** 6);
        assertEq(paymentToken.balanceOf(address(vendingMachine)), contractBalanceBefore + 1000 * 10 ** 6);
    }

    function testPermitFunds_InvalidOracleSignature() public {
        bytes32 checkoutId = keccak256("checkout_2");
        bytes memory checkoutMessage = _createCheckoutMessage(checkoutId);

        // Create invalid oracle signature
        (, uint256 wrongPk) = makeAddrAndKey("wrongOracle");
        bytes memory wrongSignature = _signMessage(checkoutMessage, wrongPk);

        bytes memory buyerCheckoutSignature = _signMessage(checkoutMessage, buyerPk);
        bytes memory buyerAuthData = _createBuyerAuth(checkoutMessage);
        bytes memory buyerAuthSignature = _signMessage(buyerAuthData, buyerPk);

        vm.expectRevert("TokenVendingMachine: Invalid signature.");
        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            checkoutMessage, buyerCheckoutSignature, wrongSignature, buyerAuthData, buyerAuthSignature
        );
    }

    function testPermitFunds_InvalidBuyerSignature() public {
        bytes32 checkoutId = keccak256("checkout_3");
        bytes memory checkoutMessage = _createCheckoutMessage(checkoutId);

        bytes memory oracleSignature = _signMessage(checkoutMessage, oraclePk);
        bytes memory buyerCheckoutSignature = _signMessage(checkoutMessage, buyerPk);
        bytes memory buyerAuthData = _createBuyerAuth(checkoutMessage);

        // Invalid buyer auth signature
        (, uint256 wrongBuyerPk) = makeAddrAndKey("wrongBuyer");
        bytes memory wrongBuyerAuthSignature = _signMessage(buyerAuthData, wrongBuyerPk);

        vm.expectRevert("TokenVendingMachine: Invalid buyer signature.");
        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            checkoutMessage, buyerCheckoutSignature, oracleSignature, buyerAuthData, wrongBuyerAuthSignature
        );
    }

    function testPermitFunds_AlreadyProcessed() public {
        // First checkout
        PermitFundsData memory data1 = _preparePermitFundsData(keccak256("checkout_4"));

        // First execution should succeed
        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data1.checkoutMessage,
            data1.buyerCheckoutSignature,
            data1.oracleSignature,
            data1.buyerAuthData,
            data1.buyerAuthSignature
        );

        // Prepare second checkout with same checkoutId (new permit since nonce changed)
        PermitFundsData memory data2 = _preparePermitFundsData(keccak256("checkout_4"));

        // Second execution should fail due to duplicate checkout ID
        vm.expectRevert("TokenVendingMachine: Checkout with checkoutId was already processed.");
        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data2.checkoutMessage,
            data2.buyerCheckoutSignature,
            data2.oracleSignature,
            data2.buyerAuthData,
            data2.buyerAuthSignature
        );
    }

    function testPermitFunds_OnlyTrustedCaller() public {
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_5"));
        address nonTrustedCaller = makeAddr("nonTrustedCaller");

        vm.expectRevert();
        vm.prank(nonTrustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );
    }

    // ============================================
    // Buyback Tests
    // ============================================

    function _createBuybackAuth(bytes32 checkoutMessageHash) internal view returns (bytes memory) {
        TokenVendingMachine.BuybackAuthorization memory auth = TokenVendingMachine.BuybackAuthorization({
            checkoutId: checkoutMessageHash,
            token: address(paymentToken),
            amount: 1000 * 10 ** 6
        });
        return abi.encode(auth);
    }

    function testBuyback_Success() public {
        // First, execute a successful checkout
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_buyback_1"));
        bytes32 checkoutMessageHash = keccak256(data.checkoutMessage);

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        // Verify checkout is current (exists and not bought back)
        assertTrue(vendingMachine.current(checkoutMessageHash));
        assertTrue(vendingMachine.exists(checkoutMessageHash));

        // Prepare buyback authorization signed by buyer
        bytes memory buybackAuthData = _createBuybackAuth(checkoutMessageHash);
        bytes memory buybackAuthSignature = _signMessage(buybackAuthData, buyerPk);

        uint256 buyerBalanceBefore = paymentToken.balanceOf(buyer);
        uint256 buybackAdminBalanceBefore = paymentToken.balanceOf(buybackAdmin);

        // Execute buyback
        vm.expectEmit(true, true, true, true);
        emit BuybackSuccess(checkoutMessageHash, address(paymentToken), 1000 * 10 ** 6);

        vm.prank(buybackAdmin);
        vendingMachine.buyback(checkoutMessageHash, buybackAuthData, buybackAuthSignature);

        // Verify checkout is no longer current (bought back)
        assertFalse(vendingMachine.current(checkoutMessageHash));
        assertTrue(vendingMachine.exists(checkoutMessageHash)); // Still exists, just marked as bought back

        // Verify refund was transferred
        assertEq(paymentToken.balanceOf(buyer), buyerBalanceBefore + 1000 * 10 ** 6);
        assertEq(paymentToken.balanceOf(buybackAdmin), buybackAdminBalanceBefore - 1000 * 10 ** 6);
    }

    function testBuyback_InvalidSignature() public {
        // Execute a checkout first
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_buyback_2"));
        bytes32 checkoutMessageHash = keccak256(data.checkoutMessage);

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        // Create buyback auth signed by wrong account
        bytes memory buybackAuthData = _createBuybackAuth(checkoutMessageHash);
        (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
        bytes memory wrongSignature = _signMessage(buybackAuthData, wrongPk);

        // Should revert due to invalid signature
        vm.expectRevert("TokenVendingMachine: Invalid buyback signature.");
        vm.prank(buybackAdmin);
        vendingMachine.buyback(checkoutMessageHash, buybackAuthData, wrongSignature);
    }

    function testBuyback_CheckoutNotCurrent() public {
        bytes32 nonExistentCheckout = keccak256("nonexistent");
        bytes memory buybackAuthData = _createBuybackAuth(nonExistentCheckout);
        bytes memory buybackAuthSignature = _signMessage(buybackAuthData, buyerPk);

        // Should revert because checkout doesn't exist
        vm.expectRevert("checkout status invalid");
        vm.prank(buybackAdmin);
        vendingMachine.buyback(nonExistentCheckout, buybackAuthData, buybackAuthSignature);
    }

    function testBuyback_AlreadyBoughtBack() public {
        // Execute a checkout
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_buyback_3"));
        bytes32 checkoutMessageHash = keccak256(data.checkoutMessage);

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        // First buyback
        bytes memory buybackAuthData = _createBuybackAuth(checkoutMessageHash);
        bytes memory buybackAuthSignature = _signMessage(buybackAuthData, buyerPk);

        vm.prank(buybackAdmin);
        vendingMachine.buyback(checkoutMessageHash, buybackAuthData, buybackAuthSignature);

        // Try to buyback again - should fail
        vm.expectRevert("checkout status invalid");
        vm.prank(buybackAdmin);
        vendingMachine.buyback(checkoutMessageHash, buybackAuthData, buybackAuthSignature);
    }

    function testBuyback_OnlyTrustedBuybackRole() public {
        // Execute a checkout
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_buyback_4"));
        bytes32 checkoutMessageHash = keccak256(data.checkoutMessage);

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        // Prepare buyback
        bytes memory buybackAuthData = _createBuybackAuth(checkoutMessageHash);
        bytes memory buybackAuthSignature = _signMessage(buybackAuthData, buyerPk);

        // Try buyback from non-trusted address
        address nonTrustedBuybackRole = makeAddr("nonTrustedBuybackRole");
        vm.expectRevert();
        vm.prank(nonTrustedBuybackRole);
        vendingMachine.buyback(checkoutMessageHash, buybackAuthData, buybackAuthSignature);
    }

    function testBuyback_CheckoutStatusTransitions() public {
        // Execute a checkout
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_buyback_5"));
        bytes32 checkoutMessageHash = keccak256(data.checkoutMessage);

        // Initially, checkout doesn't exist
        assertFalse(vendingMachine.exists(checkoutMessageHash));
        assertFalse(vendingMachine.current(checkoutMessageHash));

        // After permitFunds, checkout exists and is current
        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        assertTrue(vendingMachine.exists(checkoutMessageHash));
        assertTrue(vendingMachine.current(checkoutMessageHash));

        // After buyback, checkout exists but is not current
        bytes memory buybackAuthData = _createBuybackAuth(checkoutMessageHash);
        bytes memory buybackAuthSignature = _signMessage(buybackAuthData, buyerPk);

        vm.prank(buybackAdmin);
        vendingMachine.buyback(checkoutMessageHash, buybackAuthData, buybackAuthSignature);

        assertTrue(vendingMachine.exists(checkoutMessageHash));
        assertFalse(vendingMachine.current(checkoutMessageHash));
    }

    // ============================================
    // Withdraw Funds Tests
    // ============================================

    function testWithdrawFunds_Success() public {
        // First, execute a checkout to get funds into the contract
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_withdraw_1"));

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        uint256 contractBalance = paymentToken.balanceOf(address(vendingMachine));
        assertEq(contractBalance, 1000 * 10 ** 6);

        address recipient = makeAddr("recipient");
        uint256 withdrawAmount = 500 * 10 ** 6;

        // Withdraw funds as admin
        vm.prank(admin);
        vendingMachine.withdrawFunds(address(paymentToken), recipient, withdrawAmount);

        // Verify balances
        assertEq(paymentToken.balanceOf(recipient), withdrawAmount);
        assertEq(paymentToken.balanceOf(address(vendingMachine)), contractBalance - withdrawAmount);
    }

    function testWithdrawFunds_FullBalance() public {
        // Execute a checkout
        PermitFundsData memory data = _preparePermitFundsData(keccak256("checkout_withdraw_2"));

        vm.prank(trustedCaller);
        vendingMachine.permitFunds(
            data.checkoutMessage,
            data.buyerCheckoutSignature,
            data.oracleSignature,
            data.buyerAuthData,
            data.buyerAuthSignature
        );

        uint256 contractBalance = paymentToken.balanceOf(address(vendingMachine));
        address recipient = makeAddr("recipient");

        // Withdraw all funds
        vm.prank(admin);
        vendingMachine.withdrawFunds(address(paymentToken), recipient, contractBalance);

        assertEq(paymentToken.balanceOf(recipient), contractBalance);
        assertEq(paymentToken.balanceOf(address(vendingMachine)), 0);
    }

    function testWithdrawFunds_OnlyAdmin() public {
        address nonAdmin = makeAddr("nonAdmin");
        address recipient = makeAddr("recipient");

        vm.expectRevert("TokenVendingMachine: Caller is missing role ADMIN.");
        vm.prank(nonAdmin);
        vendingMachine.withdrawFunds(address(paymentToken), recipient, 1000 * 10 ** 6);
    }

    function testWithdrawFunds_ZeroAddress() public {
        vm.expectRevert("TokenVendingMachine: Cannot withdraw to zero address");
        vm.prank(admin);
        vendingMachine.withdrawFunds(address(paymentToken), address(0), 1000 * 10 ** 6);
    }

    function testWithdrawFunds_ZeroAmount() public {
        address recipient = makeAddr("recipient");

        vm.expectRevert("TokenVendingMachine: Amount must be greater than zero");
        vm.prank(admin);
        vendingMachine.withdrawFunds(address(paymentToken), recipient, 0);
    }

    function testWithdrawFunds_InsufficientBalance() public {
        address recipient = makeAddr("recipient");
        uint256 largeAmount = 10000 * 10 ** 6;

        // Contract has no balance, should revert
        vm.expectRevert();
        vm.prank(admin);
        vendingMachine.withdrawFunds(address(paymentToken), recipient, largeAmount);
    }
}
