// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "./RoyaltyPaymentSplitter.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC2981Upgradeable.sol";

/**
 * @title RoyaltyPaymentSplitterFactory
 * @dev Factory contract to manage RoyaltyPaymentSplitter clones and batch operations
 */
contract RoyaltyPaymentSplitterFactory {
    using Clones for address;

    event PaymentSplitterCreated(uint256 indexed tokenId, address indexed splitter, address indexed tokenOwner);

    address public immutable implementation;
    address public registryContract;
    uint96 public ownerShares;
    uint96 public constant TOTAL_SHARES = 10000;
    // tokenId => payment splitter address
    mapping(uint256 => bool) public paymentSplitterCreated;

    /**
     * @dev Constructor
     * @param ownerShares_ The number of shares for the owner
     */
    constructor(uint96 ownerShares_) {
        require(ownerShares_ <= TOTAL_SHARES, "Factory: Invalid owner shares");
        ownerShares = ownerShares_;
        implementation = address(new RoyaltyPaymentSplitter());
    }

    function registryContractSigningIn() external {
        require(registryContract == address(0), "Factory: Registry contract already set");
        registryContract = msg.sender;
    }

    /**
     * @dev Create a deterministic clone for a specific token
     * @param tokenId The token ID to create splitter for
     * @param tokenOwner The owner of the token (receives 80%)
     * @return splitter The address of the created payment splitter
     */
    function createPaymentSplitter(uint256 tokenId, address tokenOwner) external returns (address splitter) {
        require(tokenOwner != address(0), "Factory: Invalid token owner");
        if (ownerShares == 0) return address(0); // do not create splitter if owner shares are 0
        // Create deterministic clone using tokenId as salt
        splitter = Clones.cloneDeterministic(implementation, bytes32(tokenId));

        // Initialize the clone
        RoyaltyPaymentSplitter(payable(splitter)).initialize(tokenOwner, registryContract, ownerShares, TOTAL_SHARES);

        // Store the mapping
        paymentSplitterCreated[tokenId] = true;
        emit PaymentSplitterCreated(tokenId, splitter, tokenOwner);
    }

    /**
     * @dev Get the predicted address for a payment splitter without creating it
     * @param tokenId The token ID
     * @return The predicted address of the payment splitter
     */
    function predictPaymentSplitterAddress(uint256 tokenId) public view returns (address) {
        return Clones.predictDeterministicAddress(implementation, bytes32(tokenId));
    }

    function getPaymentSplitterAddress(uint256 tokenId) public view returns (address) {
        (address splitter,) = IERC2981Upgradeable(registryContract).royaltyInfo(tokenId, 0);
        return splitter;
    }

    /**
     * @dev Batch collect treasury payments from multiple token payment splitters
     * @param tokenIds Array of token IDs to collect from
     */
    function batchCollectTreasuryPayments(uint256[] calldata tokenIds) external {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            if (paymentSplitterCreated[tokenIds[i]]) {
                address payable splitter = payable(getPaymentSplitterAddress(tokenIds[i]));
                // Try to release treasury payment
                try RoyaltyPaymentSplitter(splitter).releaseToTreasury() {
                        // Success - payment was released
                } catch {
                    // Failed - might be no payment due or other issue
                    // Continue with next splitter
                }
                
            }
        }
    }

    /**
     * @dev Batch collect treasury payments from multiple token payment splitters
     * @param tokenIds Array of token IDs to collect from
     */
    function batchCollectTreasuryTokenPayments(uint256[] calldata tokenIds, address[] calldata tokens) external {
        require(tokenIds.length == tokens.length, "Factory: Input arrays must have the same length");

        for (uint256 i = 0; i < tokenIds.length; i++) {
            if (paymentSplitterCreated[tokenIds[i]]) {
                address payable splitter = payable(getPaymentSplitterAddress(tokenIds[i]));
                // Try to release treasury payment
                try RoyaltyPaymentSplitter(splitter).releaseToTreasury(IERC20(tokens[i])) {
                    // Success - payment was released
                } catch {
                    // Failed - might be no payment due or other issue
                    // Continue with next splitter
                }
            }
        }
    }

    /**
     * @dev Get releasable amounts for treasury across multiple token splitters
     * @param tokenIds Array of token IDs to check
     * @return amounts Array of releasable amounts for each token
     * @return totalReleasable Total releasable amount across all tokens
     */
    function getReleasableTreasuryAmounts(uint256[] calldata tokenIds)
        external
        view
        returns (uint256[] memory amounts, uint256 totalReleasable)
    {
        amounts = new uint256[](tokenIds.length);

        for (uint256 i = 0; i < tokenIds.length; i++) {
            if (paymentSplitterCreated[tokenIds[i]]) {
                address payable splitter = payable(getPaymentSplitterAddress(tokenIds[i]));
                amounts[i] = RoyaltyPaymentSplitter(splitter).treasuryReleasable();
                totalReleasable += amounts[i];
            }
        }
    }

    function setOwnerShares(uint96 _ownerShares) external {
        require(msg.sender == registryContract, "Factory: Only registry contract can call this function");
        ownerShares = _ownerShares;
    }
}
