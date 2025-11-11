// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interface/ITokenRegistry.sol";
import "./interface/IEIP3009.sol";
import "./interface/permit2/ISignatureTransfer.sol";
import "./OrderbookAccessControl.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC2981Upgradeable.sol";
import {TrustedSignatureChecker} from "./utils/TrustedSignatureChecker.sol";

struct EIP4494Permit {
    address owner;
    address spender;
    uint256 tokenId;
    uint256 deadline;
    bytes4 salt;
}

// Permit2 SignatureTransfer permit
struct Permit2Transfer {
    uint256 amount; // amount to transfer
    uint256 nonce; // unique nonce for signature transfer
    uint256 deadline; // signature deadline
}

struct Bid {
    bytes4 salt;
    address bidder;
    uint256 deadline;
    uint256 feeBps; // unity = 10000; total fee including royalty and platform fee
    uint256 tokenId;
    Permit2Transfer permit;
    bytes permitSignature;
}

struct Ask {
    bytes4 salt;
    uint256 deadline;
    uint256 usdcAmount;
    EIP4494Permit permit;
    bytes permitSignature;
}

struct Trade {
    bytes4 salt;
    uint256 deadline;
    Bid bid;
    Ask ask;
    bytes bidSignature;
    bytes askSignature;
}

contract Orderbook is Initializable, EIP712Upgradeable, OrderbookAccessControl, UUPSUpgradeable {
    IERC721 public registryERC721;
    ITokenRegistry public tokenRegistry;
    IEIP3009 public usdc;

    //bytes public constant EIP4494_PERMIT_TYPE = "EIP4494Permit(address owner,address spender,uint256 tokenId,uint256 deadline,bytes4 salt)";
    //bytes32 public constant EIP4494_PERMIT_TYPEHASH = keccak256(EIP4494_PERMIT_TYPE);
    bytes32 public constant EIP4494_PERMIT_TYPEHASH = 0xf545647804ae149c37d476ab2cfdbe1089b41916ab144f79326377246a049462;

    // bytes public constant PERMIT2_TRANSFER_TYPE = "Permit2Transfer(uint256 amount,uint256 nonce,uint256 deadline)";
    //bytes32 public constant PERMIT2_TRANSFER_TYPEHASH = keccak256(PERMIT2_TRANSFER_TYPE);
    bytes32 public constant PERMIT2_TRANSFER_TYPEHASH =
        0xe1042fb7954ff9d03d09f57940ce4462dbc73e3063f1e1fd0f0afac36bc49451;

    // bytes public constant  Ask_TYPE = "Ask(bytes4 salt,uint256 deadline,uint256 usdcAmount,EIP4494Permit permit,bytes permitSignature)EIP4494Permit(address owner,address spender,uint256 tokenId,uint256 deadline,bytes4 salt)";
    // bytes32 public constant ASK_TYPEHASH = keccak256(Ask_TYPE);
    bytes32 public constant ASK_TYPEHASH = 0xca02aa5d9045779f01725b9928079e26afd9bf4b4d3f58345eb8a89d08808ddd;

    // bytes public constant  Bid_TYPE = "Bid(bytes4 salt,address bidder,uint256 deadline,uint256 feeBps,uint256 tokenId,Permit2Transfer permit,bytes permitSignature)Permit2Transfer(uint256 amount,uint256 nonce,uint256 deadline)";
    // bytes32 public constant BID_TYPEHASH = keccak256(Bid_TYPE);
    bytes32 public constant BID_TYPEHASH = 0x5e2573c176eaba1f8e817452c7374281f40a5db2061a279a52990ed22ac39610;

    // bytes public constant  Trade_TYPE = "Trade(bytes4 salt,uint256 deadline,Bid bid,Ask ask,bytes bidSignature,bytes askSignature)Ask(bytes4 salt,uint256 deadline,uint256 usdcAmount,EIP4494Permit permit,bytes permitSignature)Bid(bytes4 salt,address bidder,uint256 deadline,uint256 feeBps,uint256 tokenId,Permit2Transfer permit,bytes permitSignature)EIP4494Permit(address owner,address spender,uint256 tokenId,uint256 deadline,bytes4 salt)Permit2Transfer(uint256 amount,uint256 nonce,uint256 deadline)";
    // bytes32 public constant TRADE_TYPEHASH = keccak256(Trade_TYPE);
    bytes32 public constant TRADE_TYPEHASH = 0x170fff74098bbe4e1a978004d40848beab71e6ad2988861b82892fd6bc18e099;

    address public tradeFeeRecipient;
    uint256 public constant BPS_100_PERCENT = 10000;

    address public constant PERMIT2_ADDRESS = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    mapping(bytes32 => bool) public usedEIP4494Permits;
    mapping(bytes32 => bool) public usedBids;
    mapping(bytes32 => bool) public usedAsks;
    mapping(bytes32 => bool) public usedTrades;

    event EIP4494PermitUsed(
        address indexed owner,
        address indexed spender,
        uint256 indexed tokenId,
        uint256 deadline,
        bytes4 salt,
        bytes signature
    );

    event TradeExecuted(
        address indexed bidder,
        address indexed asker,
        uint256 indexed nftTokenId,
        address erc20Token,
        uint256 amount,
        bytes tradeSignature,
        uint256 feeAccrued
    );

    /**
     * @notice Initializes the Orderbook contract
     * @dev Sets up EIP712 domain separator and contract dependencies
     * @param _registry Address of the NFT registry contract
     * @param name EIP712 domain name for signature verification
     * @param version EIP712 domain version for signature verification
     * @param _usdc Address of the USDC token contract implementing EIP3009
     */
    function initialize(
        address _registry,
        string memory name,
        string memory version,
        address _usdc,
        address _tradeFeeRecipient
    ) public initializer {
        __EIP712_init(name, version);
        __OrderbookAccessControl_init();
        __UUPSUpgradeable_init();
        registryERC721 = IERC721(_registry);
        tokenRegistry = ITokenRegistry(_registry);
        usdc = IEIP3009(_usdc);
        tradeFeeRecipient = _tradeFeeRecipient;
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract.
     * Called by {upgradeTo} and {upgradeToAndCall}.
     * @param newImplementation address of the new implementation
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    function setTradeFeeRecipient(address _tradeFeeRecipient) public onlyAdmin {
        tradeFeeRecipient = _tradeFeeRecipient;
    }

    /**
     * @notice Computes the EIP712 hash for an EIP4494 NFT permit
     * @dev Uses the contract's domain separator for proper EIP712 compliance
     * @param eip4494Permit The NFT permit data to hash
     * @return The EIP712 compliant hash of the permit
     */
    function hashPermit(EIP4494Permit calldata eip4494Permit) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    EIP4494_PERMIT_TYPEHASH,
                    eip4494Permit.owner,
                    eip4494Permit.spender,
                    eip4494Permit.tokenId,
                    eip4494Permit.deadline,
                    eip4494Permit.salt
                )
            )
        );
    }

    /**
     * @notice Executes an EIP4494 NFT permit to approve token spending
     * @dev Verifies signature, checks ownership, and approves the spender
     * @param eip4494Permit The NFT permit containing approval details
     * @param signature The permit signature from the token owner
     * @custom:security Only callable by trusted traders
     * @custom:security Prevents replay attacks using permit digest tracking
     */
    function permit(EIP4494Permit calldata eip4494Permit, bytes memory signature) private {
        require(eip4494Permit.deadline >= block.timestamp, "EIP4494Permit: Permit expired");

        bytes32 digest = hashPermit(eip4494Permit);
        require(!usedEIP4494Permits[digest], "EIP4494Permit: Permit already used");

        // address signer = ECDSA.recover(digest, signature);
        // allow both ECDSA and ERC1271 signatures
        require(
            TrustedSignatureChecker.isValidSignatureNow(eip4494Permit.owner, digest, signature, address(this)),
            "EIP4494Permit: invalid signature"
        );
        // FROM
        // require(signer == eip4494Permit.owner, "EIP4494Permit: Invalid signature");

        require(tokenRegistry.ownerOf(eip4494Permit.tokenId) == eip4494Permit.owner, "EIP4494Permit: Not token owner");

        usedEIP4494Permits[digest] = true;

        registryERC721.approve(eip4494Permit.spender, eip4494Permit.tokenId);
        emit EIP4494PermitUsed(
            eip4494Permit.owner,
            eip4494Permit.spender,
            eip4494Permit.tokenId,
            eip4494Permit.deadline,
            eip4494Permit.salt,
            signature
        );
    }

    /**
     * @notice Transfers an NFT using an EIP4494 permit
     * @dev Combines permit execution with immediate transfer in one transaction
     * @param eip4494Permit The NFT permit containing transfer authorization
     * @param to The recipient address for the NFT
     * @param signature The permit signature from the token owner
     * @custom:security Only callable by trusted traders
     */
    function transferFromWithPermit(EIP4494Permit calldata eip4494Permit, address to, bytes memory signature) private {
        permit(eip4494Permit, signature);
        registryERC721.transferFrom(eip4494Permit.owner, to, eip4494Permit.tokenId);
    }

    /**
     * @notice Validates a bid and its signature
     * @dev Verifies bid deadline, signature authenticity, and prevents replay attacks
     * @param bid The bid data containing payment authorization
     * @param signature The bid signature from the bidder
     * @return The hash of the validated bid for trade verification
     * @custom:security Marks bid as used to prevent replay attacks
     */
    function checkBid(Bid calldata bid, bytes memory signature) private returns (bytes32) {
        require(bid.deadline >= block.timestamp, "Bid expired");
        // Calculate nested struct hashes for EIP712
        bytes32 bidPermitHash = keccak256(abi.encode(PERMIT2_TRANSFER_TYPEHASH, bid.permit.amount, bid.permit.nonce, bid.permit.deadline));

        bytes32 bidHash = keccak256(
            abi.encode(
                BID_TYPEHASH,
                bid.salt,
                bid.bidder,
                bid.deadline,
                bid.feeBps,
                bid.tokenId,
                bidPermitHash,
                keccak256(bid.permitSignature)
            )
        );

        bytes32 bidDigest = _hashTypedDataV4(bidHash);
        address bidSigner = ECDSA.recover(bidDigest, signature);
        require(bidSigner == bid.bidder, "Invalid bid signature");
        require(!usedBids[bidDigest], "Bid already used");
        usedBids[bidDigest] = true;
        return bidHash;
    }

    /**
     * @notice Validates an ask and its signature
     * @dev Verifies ask deadline, signature authenticity, and prevents replay attacks
     * @param ask The ask data containing NFT sale authorization
     * @param signature The ask signature from the NFT owner
     * @return The hash of the validated ask for trade verification
     * @custom:security Marks ask as used to prevent replay attacks
     */
    function checkAsk(Ask calldata ask, bytes memory signature) private returns (bytes32) {
        require(ask.deadline >= block.timestamp, "Ask expired");
        bytes32 askPermitHash = keccak256(
            abi.encode(
                EIP4494_PERMIT_TYPEHASH,
                ask.permit.owner,
                ask.permit.spender,
                ask.permit.tokenId,
                ask.permit.deadline,
                ask.permit.salt
            )
        );

        bytes32 askHash = keccak256(
            abi.encode(
                ASK_TYPEHASH, ask.salt, ask.deadline, ask.usdcAmount, askPermitHash, keccak256(ask.permitSignature)
            )
        );

        bytes32 askDigest = _hashTypedDataV4(askHash);
        // address askSigner = ECDSA.recover(askDigest, signature);
        require(
            TrustedSignatureChecker.isValidSignatureNow(ask.permit.owner, askDigest, signature, address(this)),
            "Invalid ask signature"
        );

        // require(askSigner == ask.permit.owner, "Invalid ask signature");
        require(!usedAsks[askDigest], "Ask already used");
        usedAsks[askDigest] = true;
        return askHash;
    }

    /**
     * @notice Executes a trade between a bid and ask
     * @dev Validates all signatures, transfers USDC and NFT, handles refunds
     * @param trade The complete trade data containing bid, ask, and execution details
     * @param signature The trade signature from the trusted trader
     * @custom:security Only callable by trusted callers
     * @custom:security Validates bid amount covers ask price
     * @custom:security Ensures NFT IDs match between bid and ask
     * @custom:security Automatically refunds excess bid amount to bidder
     * @custom:flow 1. Validates trade parameters and signatures
     * @custom:flow 2. Pulls USDC from bidder using EIP3009 permit
     * @custom:flow 3. Refunds excess amount if bid > ask
     * @custom:flow 4. Transfers ask amount to seller
     * @custom:flow 5. Transfers NFT to bidder using EIP4494 permit
     */
    function executeTrade(Trade calldata trade, bytes memory signature) public onlyTrustedCaller {
        require(trade.deadline >= block.timestamp, "Permit expired");
        require(trade.bid.tokenId == trade.ask.permit.tokenId, "NFT ID mismatch");

        // Validate signatures
        _validateTradeSignature(trade, signature);

        // Execute payment with new fee logic
        uint256 feeUSDC = _executeTradePayment(trade);

        // Send the nft to the bidder
        transferFromWithPermit(trade.ask.permit, trade.bid.bidder, trade.ask.permitSignature);

        _emitTradeExecuted(trade, signature, feeUSDC);
    }

    function _validateTradeSignature(Trade calldata trade, bytes memory signature) private {
        bytes32 bidHash = checkBid(trade.bid, trade.bidSignature);
        bytes32 askHash = checkAsk(trade.ask, trade.askSignature);

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    TRADE_TYPEHASH,
                    trade.salt,
                    trade.deadline,
                    bidHash,
                    askHash,
                    keccak256(trade.bidSignature),
                    keccak256(trade.askSignature)
                )
            )
        );
        require(hasTrustedTraderRole(ECDSA.recover(digest, signature)), "Trade: invalid signature");
    }

    function _executeTradePayment(Trade calldata trade) private returns (uint256) {
        uint256 baseAmount = trade.ask.usdcAmount;
        uint256 totalFee = 0;
        uint256 royaltyAmount = 0;
        address royaltyReceiver;

        if (trade.bid.feeBps > 0) {
            // New payment model: ask.usdcAmount includes fees
            // Calculate base amount: ask.usdcAmount = base * (1 + feeBps%)
            // Example: ask = 105, feeBps = 500 (5%) => base = 100, totalFee = 5
            require(trade.bid.feeBps <= BPS_100_PERCENT, "Trade: fee too high");
            baseAmount = (trade.ask.usdcAmount * BPS_100_PERCENT) / (BPS_100_PERCENT + trade.bid.feeBps); 
            totalFee = trade.ask.usdcAmount - baseAmount;
            
            // Calculate royalty on the base amount (royalty is part of the total fee)
            (royaltyReceiver, royaltyAmount) =
                IERC2981Upgradeable(address(tokenRegistry)).royaltyInfo(trade.ask.permit.tokenId, baseAmount);
            require(totalFee >= royaltyAmount, "Total fee must be greater than royalty amount");

            // Total required is just the ask amount (fee already included)
            require(trade.bid.permit.amount >= trade.ask.usdcAmount, "Bid cant cover Ask + fees");

            // Pull USDC from bidder
            _pullUSDCFromBidder(trade);

            // Refund excess
            uint256 refund = trade.bid.permit.amount - trade.ask.usdcAmount;
            if (refund > 0) {
                usdc.transfer(trade.bid.bidder, refund);
            }

            // Distribute payments
            if (totalFee > royaltyAmount) {
                usdc.transfer(tradeFeeRecipient, totalFee - royaltyAmount);
            }
            if (royaltyAmount > 0) {
                usdc.transfer(royaltyReceiver, royaltyAmount);
            }
            // Seller receives base amount
            usdc.transfer(trade.ask.permit.owner, baseAmount);
        } else {
            // Old payment model: feeBps = 0, royalty paid separately
            // baseAmount = askPrice, bidder must pay askPrice + royalty
            (royaltyReceiver, royaltyAmount) =
                IERC2981Upgradeable(address(tokenRegistry)).royaltyInfo(trade.ask.permit.tokenId, baseAmount);
            
            uint256 totalRequired = baseAmount + royaltyAmount;
            require(trade.bid.permit.amount >= totalRequired, "Bid cant cover Ask + royalty");

            // Pull USDC from bidder
            _pullUSDCFromBidder(trade);

            // Refund excess
            uint256 refund = trade.bid.permit.amount - totalRequired;
            if (refund > 0) {
                usdc.transfer(trade.bid.bidder, refund);
            }

            // Distribute payments
            if (royaltyAmount > 0) {
                usdc.transfer(royaltyReceiver, royaltyAmount);
            }
            // Seller receives full ask amount
            usdc.transfer(trade.ask.permit.owner, baseAmount);
        }

        return totalFee;
    }

    function _pullUSDCFromBidder(Trade calldata trade) private {
        ISignatureTransfer PERMIT2 = ISignatureTransfer(PERMIT2_ADDRESS);

        PERMIT2.permitTransferFrom(
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({
                    token: address(usdc),
                    amount: trade.bid.permit.amount
                }),
                nonce: trade.bid.permit.nonce,
                deadline: trade.bid.permit.deadline
            }),
            ISignatureTransfer.SignatureTransferDetails({
                to: address(this),
                requestedAmount: trade.bid.permit.amount
            }),
            trade.bid.bidder,
            trade.bid.permitSignature
        );
    }

    function _payRoyalty(uint256 tokenId, uint256 usdcAmount) private returns (uint256) {
        // handle royalty
        (address infoReceiver, uint256 infoAmount) =
            IERC2981Upgradeable(address(tokenRegistry)).royaltyInfo(tokenId, usdcAmount);
        if (infoReceiver != address(0) && infoAmount > 0) {
            usdc.transfer(infoReceiver, infoAmount);
            usdcAmount = usdcAmount - infoAmount;
        }
        return usdcAmount;
    }

    function _emitTradeExecuted(Trade calldata trade, bytes memory signature, uint256 feeUSDC) private {
        emit TradeExecuted(
            trade.bid.bidder,
            trade.ask.permit.owner,
            trade.ask.permit.tokenId,
            address(usdc),
            trade.ask.usdcAmount,
            signature,
            feeUSDC
        );
    }

    /**
     * @notice Returns the EIP712 domain separator for this contract
     * @dev Used for signature verification and EIP712 compliance
     * @return The domain separator hash
     */
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function implementation() external view returns (address) {
        return _getImplementation();
    }
}
