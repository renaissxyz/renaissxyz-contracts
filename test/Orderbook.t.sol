// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "forge-std/Test.sol";
import {Orderbook, Permit2Transfer, EIP4494Permit, Bid, Ask, Trade} from "../src/Orderbook.sol";
import {RenaissRegistry} from "../src/RenaissRegistry.sol";
import {RenaissRegistryV3} from "../src/RenaissRegistryV3.sol";
import {RoyaltyPaymentSplitterFactory} from "../src/RoyaltyPaymentSplitterFactory.sol";
import {MockERC20} from "./mock/MockERC20.sol";
import {IAllowanceTransfer} from "../src/interface/permit2/IAllowanceTransfer.sol";
import {IEIP712} from "../src/interface/permit2/IEIP712.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./utils/Permit2Deployer.sol";

// Mock trusted contract signer (ERC1271)
contract MockTrustedContract is IERC1271 {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        address signer = ECDSA.recover(hash, signature);
        console.log("isValidSignature:");
        console.log("signer", signer);
        console.log("owner", owner);
        if (signer == owner) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

contract OrderbookTest is Permit2Deployer {
    Orderbook public orderbook;
    RenaissRegistry public registry;
    RoyaltyPaymentSplitterFactory public factory;
    MockERC20 public usdc;
    MockTrustedContract public trustedContract;

    address public admin = makeAddr("admin");
    address public trustedTrader = makeAddr("trustedTrader");
    address public bidder = makeAddr("bidder");
    address public seller = makeAddr("seller");
    address public treasury = makeAddr("treasury");
    address public tradeFeeRecipient = makeAddr("tradeFeeRecipient");
    address public nonTrustedContract = makeAddr("nonTrustedContract");

    uint256 public trustedTraderPK = 0xA11CE;
    uint256 public bidderPK = 0xB0B;
    uint256 public sellerPK = 0xABCD;

    bytes32 public constant PROOF_OF_INTEGRITY = keccak256("test_proof");
    uint256 public constant TOKEN_ID = uint256(PROOF_OF_INTEGRITY);

    event TradeExecuted(
        address indexed bidder,
        address indexed asker,
        uint256 indexed nftTokenId,
        address erc20Token,
        uint256 amount,
        bytes tradeSignature,
        uint256 feeAccrued
    );

    function setUp() public {
        vm.startPrank(admin);

        // Deploy Permit2
        deployPermit2();

        // Deploy USDC
        usdc = new MockERC20("USD Coin", "USDC", 6, 0);

        // Deploy RenaissRegistry
        RenaissRegistryV3 registryImpl = new RenaissRegistryV3();
        bytes memory registryInitData = abi.encodeWithSelector(
            RenaissRegistryV3.initialize.selector,
            admin,
            "https://api.renaiss.io/tokens/",
            "Renaiss Registry",
            "RENAISS",
            treasury
        );
        ERC1967Proxy registryProxy = new ERC1967Proxy(address(registryImpl), registryInitData);
        registry = RenaissRegistry(address(registryProxy));

        // Deploy RoyaltyPaymentSplitterFactory
        factory = new RoyaltyPaymentSplitterFactory(8000);
        registry.setRoyaltyPaymentSplitterFactory(address(factory));

        // Deploy Orderbook
        Orderbook orderbookImpl = new Orderbook();
        bytes memory orderbookInitData = abi.encodeWithSelector(
            Orderbook.initialize.selector, address(registry), "Renaiss Orderbook", "1", address(usdc), tradeFeeRecipient
        );
        ERC1967Proxy orderbookProxy = new ERC1967Proxy(address(orderbookImpl), orderbookInitData);
        orderbook = Orderbook(address(orderbookProxy));

        // Setup roles
        address calculatedTrader = vm.addr(trustedTraderPK);
        orderbook.grantTrustedTraderRole(calculatedTrader);
        orderbook.grantTrustedCallerRole(calculatedTrader);
        trustedTrader = calculatedTrader;

        // Setup trusted contract
        trustedContract = new MockTrustedContract(trustedTrader);
        orderbook.grantTrustedContractRole(address(trustedContract));

        // Grant roles to orderbook for transfers
        registry.grantTrustedOperatorRole(address(orderbook));

        // Mint NFT to seller
        registry.grantMinterRole(admin);
        seller = vm.addr(sellerPK);
        registry.mintToken(seller, PROOF_OF_INTEGRITY);

        // Mint USDC to bidder
        bidder = vm.addr(bidderPK);
        usdc.mint(bidder, 10000e6); // 10,000 USDC
        vm.stopPrank();

        // approve permit2
        vm.prank(bidder);
        usdc.approve(address(permit2), type(uint256).max);

        // approve permit2
        vm.prank(seller);
        usdc.approve(address(permit2), type(uint256).max);
    }

    function _signNftPermit(uint256 privateKey) internal returns (EIP4494Permit memory, bytes memory) {
        // Create EIP4494Permit for NFT (seller approves orderbook)
        address owner = vm.addr(privateKey);
        EIP4494Permit memory nftPermit = EIP4494Permit({
            owner: owner,
            spender: address(orderbook),
            tokenId: TOKEN_ID,
            deadline: block.timestamp + 1 hours,
            salt: bytes4(keccak256("nft_salt_1"))
        });

        bytes32 nftPermitDigest = orderbook.hashPermit(nftPermit);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, nftPermitDigest);
        return (nftPermit, abi.encodePacked(r1, s1, v1));
    }

    function _signNftPermitTrustedContract(address _trustedContract, uint256 privateKey)
        internal
        returns (EIP4494Permit memory, bytes memory)
    {
        // Create EIP4494Permit for NFT (seller approves orderbook)
        EIP4494Permit memory nftPermit = EIP4494Permit({
            owner: address(_trustedContract),
            spender: address(orderbook),
            tokenId: TOKEN_ID,
            deadline: block.timestamp + 1 hours,
            salt: bytes4(keccak256("nft_salt_1"))
        });

        bytes32 nftPermitDigest = orderbook.hashPermit(nftPermit);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, nftPermitDigest);
        return (nftPermit, abi.encodePacked(r1, s1, v1));
    }

    function _signAsk(uint256 privateKey, uint256 askPrice) internal returns (Ask memory, bytes memory, bytes memory) {
        (EIP4494Permit memory nftPermit, bytes memory nftPermitSig) = _signNftPermit(privateKey);
        // Create Ask
        Ask memory ask = Ask({
            salt: bytes4(keccak256("ask_salt_1")),
            deadline: block.timestamp + 1 hours,
            usdcAmount: askPrice,
            permit: nftPermit,
            permitSignature: nftPermitSig
        });

        bytes32 askHashDigest = _hashAsk(ask);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, askHashDigest);
        bytes memory askSig = abi.encodePacked(r2, s2, v2);
        return (ask, askSig, nftPermitSig);
    }

    function _signAskTrustedContract(uint256 privateKey, uint256 askPrice, address _trustedContract)
        internal
        returns (Ask memory, bytes memory, bytes memory)
    {
        (EIP4494Permit memory nftPermit, bytes memory nftPermitSig) =
            _signNftPermitTrustedContract(_trustedContract, privateKey);
        // Create Ask
        Ask memory ask = Ask({
            salt: bytes4(keccak256("ask_salt_1")),
            deadline: block.timestamp + 1 hours,
            usdcAmount: askPrice,
            permit: nftPermit,
            permitSignature: nftPermitSig
        });

        bytes32 askHashDigest = _hashAsk(ask);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, askHashDigest);
        bytes memory askSig = abi.encodePacked(r2, s2, v2);
        return (ask, askSig, nftPermitSig);
    }

    function _signBid(uint256 privateKey, address signer, uint256 bidAmount)
        internal
        returns (Bid memory, bytes memory)
    {
        uint256 nonce = uint256(keccak256(abi.encodePacked("bid_nonce_1", block.timestamp)));
        Permit2Transfer memory permit2 = Permit2Transfer({
            amount: bidAmount,
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });

        bytes memory permit2Sig = _signPermit2SignatureTransfer(permit2, privateKey, signer);

        // Create Bid
        Bid memory bid = Bid({
            salt: bytes4(keccak256("bid_salt_1")),
            bidder: signer,
            deadline: block.timestamp + 1 hours,
            feeBps: 0, //no fee
            tokenId: TOKEN_ID,
            permit: permit2,
            permitSignature: permit2Sig
        });

        bytes32 bidHashDigest = _hashBid(bid);
        (uint8 v4, bytes32 r4, bytes32 s4) = vm.sign(privateKey, bidHashDigest);
        bytes memory bidSig = abi.encodePacked(r4, s4, v4);
        return (bid, bidSig);
    }

    function _signTrade(uint256 privateKey, uint256 askPrice, uint256 bidAmount)
        internal
        returns (Trade memory, bytes memory)
    {
        (Bid memory bid, bytes memory bidSig) = _signBid(bidderPK, bidder, bidAmount);
        (Ask memory ask, bytes memory askSig,) = _signAsk(sellerPK, askPrice);

        Trade memory trade = Trade({
            salt: bytes4(keccak256("trade_salt_1")),
            deadline: block.timestamp + 1 hours,
            bid: bid,
            ask: ask,
            bidSignature: bidSig,
            askSignature: askSig
        });

        return (trade, _signTradeStruct(trade, privateKey));
    }

    function _signTradeWithTrustedContractAsk(uint256 privateKey, uint256 askPrice, address _trustedContract)
        internal
        returns (Trade memory, bytes memory)
    {
        // Calculate total bid amount including royalty
        (, uint256 royaltyAmount) = registry.royaltyInfo(TOKEN_ID, askPrice);

        (Bid memory bid, bytes memory bidSig) = _signBid(bidderPK, bidder, askPrice + royaltyAmount);
        (Ask memory ask, bytes memory askSig,) = _signAskTrustedContract(privateKey, askPrice, _trustedContract);

        Trade memory trade = Trade({
            salt: bytes4(keccak256("trade_salt_1")),
            deadline: block.timestamp + 1 hours,
            bid: bid,
            ask: ask,
            bidSignature: bidSig,
            askSignature: askSig
        });

        return (trade, _signTradeStruct(trade, privateKey));
    }

    function _signTradeStruct(Trade memory trade, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 tradeHash = _hashTrade(trade, _getBidHashStruct(trade.bid), _getAskHashStruct(trade.ask));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, tradeHash);
        return abi.encodePacked(r, s, v);
    }

    function testExecuteTradeWithEOASignatures() public {
        uint256 askPrice = 1000e6; // 1000 USDC (seller's listing price)

        // Calculate royalty (1% default = 100 bps)
        (address royaltyReceiver, uint256 royaltyAmount) = registry.royaltyInfo(TOKEN_ID, askPrice);

        // Buyer needs to pay: askPrice + royalty
        // No listing fee in this test (feeBps = 0)
        uint256 totalRequired = askPrice + royaltyAmount;
        uint256 bidAmount = totalRequired + 200e6; // Overpay to test refund

        (Trade memory trade, bytes memory tradeSig) = _signTrade(trustedTraderPK, askPrice, bidAmount);

        uint256 sellerBalanceBefore = usdc.balanceOf(seller);
        uint256 bidderBalanceBefore = usdc.balanceOf(bidder);
        uint256 royaltyReceiverBalanceBefore = usdc.balanceOf(royaltyReceiver);

        vm.expectEmit(true, true, true, false);
        emit TradeExecuted(bidder, seller, TOKEN_ID, address(usdc), askPrice, tradeSig, 0);

        vm.prank(trustedTrader);
        orderbook.executeTrade(trade, tradeSig);

        // Verify NFT transferred to bidder
        assertEq(registry.ownerOf(TOKEN_ID), bidder);

        // Verify payments:
        // - Seller receives full askPrice
        assertEq(usdc.balanceOf(seller), sellerBalanceBefore + askPrice);
        // - Royalty receiver gets royalty
        assertEq(usdc.balanceOf(royaltyReceiver), royaltyReceiverBalanceBefore + royaltyAmount);
        // - Bidder pays only totalRequired (gets refund of overpayment)
        assertEq(usdc.balanceOf(bidder), bidderBalanceBefore - totalRequired);
    }

    function testExecuteTradeWithListingFee() public {
        // New logic: askPrice already includes the total fee
        // Example: base = 100, feeBps = 700 (7%), royalty = 1%
        // askPrice = base * (1 + 7%) = 107
        // totalFee = 7 (includes both platform fee and royalty)
        // royalty = 100 * 1% = 1
        // platformFee = 7 - 1 = 6
        uint256 baseAmount = 100e6; // 100 USDC (what seller receives)
        uint256 feeBps = 700; // 7% total fee

        // Calculate askPrice: askPrice = base * (1 + feeBps%)
        uint256 askPrice = (baseAmount * (10000 + feeBps)) / 10000; // 107 USDC

        // Calculate expected fees
        uint256 totalFee = askPrice - baseAmount; // 7 USDC
        (, uint256 royaltyAmount) = registry.royaltyInfo(TOKEN_ID, baseAmount); // 1 USDC (1% of base)
        uint256 platformFee = totalFee - royaltyAmount; // 6 USDC

        // Total required from bidder is just the askPrice (fee already included)
        uint256 totalRequired = askPrice; // 107 USDC

        // Execute trade
        _executeTradeWithFeeAndVerify(askPrice, totalRequired, feeBps, platformFee, royaltyAmount, baseAmount);
    }

    function _executeTradeWithFeeAndVerify(
        uint256 askPrice,
        uint256 totalRequired,
        uint256 feeBps,
        uint256 platformFee,
        uint256 royaltyAmount,
        uint256 baseAmount
    ) internal {
        Trade memory trade = _createTradeWithFee(askPrice, totalRequired, feeBps);
        bytes32 tradeHash = _hashTrade(trade, _getBidHashStruct(trade.bid), _getAskHashStruct(trade.ask));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedTraderPK, tradeHash);

        uint256 sellerBefore = usdc.balanceOf(seller);
        uint256 bidderBefore = usdc.balanceOf(bidder);

        vm.prank(trustedTrader);
        orderbook.executeTrade(trade, abi.encodePacked(r, s, v));

        // Verify NFT transferred
        assertEq(registry.ownerOf(TOKEN_ID), bidder);

        // Verify payments
        // Seller receives baseAmount (not askPrice anymore)
        assertEq(usdc.balanceOf(seller) - sellerBefore, baseAmount);
        assertEq(usdc.balanceOf(bidder), bidderBefore - totalRequired);

        // Check fee and royalty separately
        _verifyFeePayments(platformFee, royaltyAmount);
    }

    function _verifyFeePayments(uint256 expectedListingFee, uint256 expectedRoyalty) internal {
        if (expectedListingFee > 0) {
            assertGt(usdc.balanceOf(tradeFeeRecipient), 0, "Fee recipient should receive listing fee");
        }
        if (expectedRoyalty > 0) {
            (address royaltyReceiver,) = registry.royaltyInfo(TOKEN_ID, 100e6);
            assertGt(usdc.balanceOf(royaltyReceiver), 0, "Royalty receiver should receive royalty");
        }
    }

    function _createTradeWithFee(uint256 askPrice, uint256 bidAmount, uint256 feeBps)
        internal
        returns (Trade memory)
    {
        uint256 nonce = uint256(keccak256(abi.encodePacked("bid_nonce_fee", block.timestamp)));
        Permit2Transfer memory permit2 = Permit2Transfer({
            amount: bidAmount,
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });
        bytes memory permit2Sig = _signPermit2SignatureTransfer(permit2, bidderPK, bidder);

        Bid memory bid = Bid({
            salt: bytes4(keccak256("bid_salt_fee")),
            bidder: bidder,
            deadline: block.timestamp + 1 hours,
            feeBps: feeBps,
            tokenId: TOKEN_ID,
            permit: permit2,
            permitSignature: permit2Sig
        });

        (Ask memory ask, bytes memory askSig,) = _signAsk(sellerPK, askPrice);

        return Trade({
            salt: bytes4(keccak256("trade_salt_fee")),
            deadline: block.timestamp + 1 hours,
            bid: bid,
            ask: ask,
            bidSignature: _signBidStruct(bid, bidderPK),
            askSignature: askSig
        });
    }

    function testExecuteTradeWithTrustedContractSignature() public {
        uint256 askPrice = 1000e6;

        // Calculate royalty
        (, uint256 royaltyAmount) = registry.royaltyInfo(TOKEN_ID, askPrice);
        uint256 bidAmount = askPrice + royaltyAmount;

        // Transfer NFT to trusted contract first
        vm.prank(seller);
        registry.transferFrom(seller, address(trustedContract), TOKEN_ID);

        (Trade memory trade, bytes memory tradeSig) =
            _signTradeWithTrustedContractAsk(trustedTraderPK, askPrice, address(trustedContract));
        // Execute trade
        vm.prank(trustedTrader);
        orderbook.executeTrade(trade, tradeSig);

        // Verify NFT transferred to bidder
        assertEq(registry.ownerOf(TOKEN_ID), bidder);
    }

    function _signBidStruct(Bid memory bid, uint256 privateKey) internal view returns (bytes memory) {
        bytes32 bidHashDigest = _hashBid(bid);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, bidHashDigest);
        return abi.encodePacked(r, s, v);
    }

    function testRevertExecuteTradeWithNonTrustedContractSignature() public {
        uint256 askPrice = 1000e6;
        (, uint256 royaltyAmount) = registry.royaltyInfo(TOKEN_ID, askPrice);
        uint256 bidAmount = askPrice + royaltyAmount;

        // Create mock non-trusted contract
        MockTrustedContract nonTrusted = new MockTrustedContract(seller);

        // Transfer NFT to non-trusted contract
        vm.prank(seller);
        registry.transferFrom(seller, address(nonTrusted), TOKEN_ID);

        (Trade memory trade, bytes memory tradeSig) =
            _signTradeWithTrustedContractAsk(trustedTraderPK, askPrice, address(nonTrusted));
        // Execute trade should revert
        vm.prank(trustedTrader);
        vm.expectRevert("Invalid ask signature");
        orderbook.executeTrade(trade, tradeSig);
    }

    function testRevertExecuteTradeByNonTrustedTrader() public {
        uint256 askPrice = 1000e6;
        uint256 bidAmount = 1000e6;

        // Create minimal trade structure
        EIP4494Permit memory nftPermit = EIP4494Permit({
            owner: seller,
            spender: address(orderbook),
            tokenId: TOKEN_ID,
            deadline: block.timestamp + 1 hours,
            salt: bytes4(keccak256("nft_salt_4"))
        });

        Ask memory ask = Ask({
            salt: bytes4(keccak256("ask_salt_4")),
            deadline: block.timestamp + 1 hours,
            usdcAmount: askPrice,
            permit: nftPermit,
            permitSignature: ""
        });

        uint256 nonce = uint256(keccak256(abi.encodePacked("bid_nonce_4", block.timestamp)));
        Permit2Transfer memory permit2 = Permit2Transfer({
            amount: bidAmount,
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });

        Bid memory bid = Bid({
            salt: bytes4(keccak256("bid_salt_4")),
            bidder: bidder,
            deadline: block.timestamp + 1 hours,
            feeBps: 0,
            tokenId: TOKEN_ID,
            permit: permit2,
            permitSignature: ""
        });

        Trade memory trade = Trade({
            salt: bytes4(keccak256("trade_salt_4")),
            deadline: block.timestamp + 1 hours,
            bid: bid,
            ask: ask,
            bidSignature: "",
            askSignature: ""
        });

        // Try to execute as non-trusted address
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert("Orderbook: Caller is missing role TRUSTED_CALLER_ROLE.");
        orderbook.executeTrade(trade, "");
    }

    // Helper functions to compute EIP712 hashes (copy from OrderBook.s.sol)
    function _hashAsk(Ask memory ask) internal view returns (bytes32) {
        bytes32 askPermitHash = keccak256(
            abi.encode(
                orderbook.EIP4494_PERMIT_TYPEHASH(),
                ask.permit.owner,
                ask.permit.spender,
                ask.permit.tokenId,
                ask.permit.deadline,
                ask.permit.salt
            )
        );

        bytes32 askHash = keccak256(
            abi.encode(
                orderbook.ASK_TYPEHASH(),
                ask.salt,
                ask.deadline,
                ask.usdcAmount,
                askPermitHash,
                keccak256(ask.permitSignature)
            )
        );

        bytes32 askDigest = keccak256(abi.encodePacked("\x19\x01", orderbook.DOMAIN_SEPARATOR(), askHash));
        return askDigest;
    }

    function _hashBid(Bid memory bid) internal view returns (bytes32) {
        bytes32 bidPermitHash =
            keccak256(abi.encode(orderbook.PERMIT2_TRANSFER_TYPEHASH(), bid.permit.amount, bid.permit.nonce, bid.permit.deadline));

        bytes32 bidHash = keccak256(
            abi.encode(
                orderbook.BID_TYPEHASH(),
                bid.salt,
                bid.bidder,
                bid.deadline,
                bid.feeBps,
                bid.tokenId,
                bidPermitHash,
                keccak256(bid.permitSignature)
            )
        );

        bytes32 bidDigest = keccak256(abi.encodePacked("\x19\x01", orderbook.DOMAIN_SEPARATOR(), bidHash));
        return bidDigest;
    }

    function _hashTrade(Trade memory trade, bytes32 bidHashStruct, bytes32 askHashStruct)
        internal
        view
        returns (bytes32)
    {
        bytes32 tradeDigest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                orderbook.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        orderbook.TRADE_TYPEHASH(),
                        trade.salt,
                        trade.deadline,
                        bidHashStruct,
                        askHashStruct,
                        keccak256(trade.bidSignature),
                        keccak256(trade.askSignature)
                    )
                )
            )
        );
        return tradeDigest;
    }

    function _signPermit2SignatureTransfer(Permit2Transfer memory permit, uint256 privateKey, address owner)
        internal
        view
        returns (bytes memory)
    {
        // Use the shared implementation from Permit2Deployer base contract
        return super._signPermit2SignatureTransfer(
            privateKey, owner, address(usdc), address(orderbook), permit.amount, permit.nonce, permit.deadline
        );
    }

    function _getBidHashStruct(Bid memory bid) internal view returns (bytes32) {
        bytes32 bidPermitHash =
            keccak256(abi.encode(orderbook.PERMIT2_TRANSFER_TYPEHASH(), bid.permit.amount, bid.permit.nonce, bid.permit.deadline));

        return keccak256(
            abi.encode(
                orderbook.BID_TYPEHASH(),
                bid.salt,
                bid.bidder,
                bid.deadline,
                bid.feeBps,
                bid.tokenId,
                bidPermitHash,
                keccak256(bid.permitSignature)
            )
        );
    }

    function _getAskHashStruct(Ask memory ask) internal view returns (bytes32) {
        bytes32 askPermitHash = keccak256(
            abi.encode(
                orderbook.EIP4494_PERMIT_TYPEHASH(),
                ask.permit.owner,
                ask.permit.spender,
                ask.permit.tokenId,
                ask.permit.deadline,
                ask.permit.salt
            )
        );

        return keccak256(
            abi.encode(
                orderbook.ASK_TYPEHASH(),
                ask.salt,
                ask.deadline,
                ask.usdcAmount,
                askPermitHash,
                keccak256(ask.permitSignature)
            )
        );
    }
}
