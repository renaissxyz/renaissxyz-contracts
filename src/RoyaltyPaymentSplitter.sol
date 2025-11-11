// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interface/ITokenRegistry.sol";

/**
 * @title RoyaltyPaymentSplitter
 * @dev Custom payment splitter for royalty distribution between token owner (80%) and Renaissance treasury (20%)
 * Based on OpenZeppelin's PaymentSplitter but designed for EIP-1167 cloning
 */
contract RoyaltyPaymentSplitter is Initializable {
    using Address for address payable;
    using SafeERC20 for IERC20;

    event PayeeAdded(address account, uint256 shares);
    event PaymentReleased(address to, uint256 amount);
    event ERC20PaymentReleased(IERC20 indexed token, address to, uint256 amount);
    event PaymentReceived(address from, uint256 amount);

    address public tokenOwner;
    address public factory;
    address public registryContract;

    uint256 private _totalReleased;
    uint256 private _ownerReleased;
    uint256 private _treasuryReleased;
    uint96 private _ownerShares;
    uint96 private _totalShares;

    mapping(IERC20 => uint256) private _erc20TotalReleased;
    mapping(IERC20 => uint256) private _erc20OwnerReleased;
    mapping(IERC20 => uint256) private _erc20TreasuryReleased;

    /**
     * @dev Constructor for implementation contract (not used directly)
     */
    constructor() {
        // Implementation contract - not initialized
    }

    /**
     * @dev Initialize the payment splitter (called on clones)
     * @param _tokenOwner Address of the token owner (receives 80%)
     * @param _registryContract Address of registry contract containing Renaissance treasury
     */
    function initialize(address _tokenOwner, address _registryContract, uint96 ownerShares_, uint96 totalShares_)
        external
        initializer
    {
        require(_tokenOwner != address(0), "RoyaltyPaymentSplitter: Invalid token owner");
        require(_registryContract != address(0), "RoyaltyPaymentSplitter: Invalid registry");

        tokenOwner = _tokenOwner;
        registryContract = _registryContract;
        factory = msg.sender;
        _ownerShares = ownerShares_;
        _totalShares = totalShares_;

        emit PayeeAdded(_tokenOwner, ownerShares_);
    }

    /**
     * @dev The Ether received will be logged with {PaymentReceived} events.
     */
    receive() external payable virtual {
        emit PaymentReceived(msg.sender, msg.value);
    }

    /**
     * @dev Getter for the total shares held by payees.
     */
    function totalShares() public view returns (uint256) {
        return _totalShares;
    }

    /**
     * @dev Getter for the total amount of Ether already released.
     */
    function totalReleased() public view returns (uint256) {
        return _totalReleased;
    }

    /**
     * @dev Getter for the total amount of `token` already released.
     */
    function totalReleased(IERC20 token) public view returns (uint256) {
        return _erc20TotalReleased[token];
    }

    /**
     * @dev Getter for the amount of shares held by an account.
     */
    function ownerShares() external view returns (uint256) {
        return _ownerShares;
    }

    /**
     * @dev Getter for the amount of Ether already released to a payee.
     */
    function ownerReleased() external view returns (uint256) {
        return _ownerReleased;
    }

    function treasuryReleased() external view returns (uint256) {
        return _treasuryReleased;
    }

    /**
     * @dev Getter for the amount of `token` tokens already released to a payee.
     */
    function ownerReleased(IERC20 token) external view returns (uint256) {
        return _erc20OwnerReleased[token];
    }

    function treasuryReleased(IERC20 token) external view returns (uint256) {
        return _erc20TreasuryReleased[token];
    }

    /**
     * @dev Getter for the amount of payee's releasable Ether.
     */
    function ownerReleasable() public view returns (uint256) {
        return _pendingPayment(tokenOwner, address(this).balance + _totalReleased, _ownerReleased);
    }

    /**
     * @dev Getter for the amount of payee's releasable `token` tokens.
     */
    function ownerReleasable(IERC20 token) public view returns (uint256) {
        return _pendingPayment(
            tokenOwner, token.balanceOf(address(this)) + _erc20TotalReleased[token], _erc20OwnerReleased[token]
        );
    }

    /**
     * @dev Getter for the amount of payee's releasable Ether.
     */
    function treasuryReleasable() public view returns (uint256) {
        return _pendingPayment(
            ITokenRegistry(registryContract).treasury(), address(this).balance + _totalReleased, _treasuryReleased
        );
    }

    /**
     * @dev Getter for the amount of payee's releasable `token` tokens.
     */
    function treasuryReleasable(IERC20 token) public view returns (uint256) {
        return _pendingPayment(
            ITokenRegistry(registryContract).treasury(),
            token.balanceOf(address(this)) + _erc20TotalReleased[token],
            _erc20TreasuryReleased[token]
        );
    }

    /**
     * @dev Triggers a transfer to `account` of the amount of Ether they are owed.
     */
    function releaseToOwner() external virtual {
        uint256 payment = ownerReleasable();
        require(payment != 0, "PaymentSplitter: owner is not due payment");

        _totalReleased += payment;
        unchecked {
            _ownerReleased += payment;
        }

        payable(tokenOwner).sendValue(payment);
        emit PaymentReleased(tokenOwner, payment);
    }

    /**
     * @dev Triggers a transfer to `account` of the amount of `token` tokens they are owed.
     */
    function releaseToOwner(IERC20 token) public virtual {
        uint256 payment = ownerReleasable(token);
        require(payment != 0, "PaymentSplitter: account is not due payment");

        _erc20TotalReleased[token] += payment;
        unchecked {
            _erc20OwnerReleased[token] += payment;
        }

        token.safeTransfer(tokenOwner, payment);
        emit ERC20PaymentReleased(token, tokenOwner, payment);
    }

    /**
     * @dev Triggers a transfer to `account` of the amount of Ether they are owed.
     */
    function releaseToTreasury() external virtual {
        address payable treasury = payable(ITokenRegistry(registryContract).treasury());
        uint256 payment = treasuryReleasable();
        require(payment != 0, "PaymentSplitter: owner is not due payment");

        _totalReleased += payment;
        unchecked {
            _treasuryReleased += payment;
        }

        treasury.sendValue(payment);
        emit PaymentReleased(treasury, payment);
    }

    /**
     * @dev Triggers a transfer to `account` of the amount of `token` tokens they are owed.
     */
    function releaseToTreasury(IERC20 token) external virtual {
        address payable treasury = payable(ITokenRegistry(registryContract).treasury());
        uint256 payment = treasuryReleasable(token);
        require(payment != 0, "PaymentSplitter: account is not due payment");

        _erc20TotalReleased[token] += payment;
        unchecked {
            _erc20TreasuryReleased[token] += payment;
        }

        token.safeTransfer(treasury, payment);
        emit ERC20PaymentReleased(token, treasury, payment);
    }

    /**
     * @dev Internal logic for computing the pending payment of an `account`.
     */
    function _pendingPayment(address account, uint256 totalReceived, uint256 alreadyReleased)
        private
        view
        returns (uint256)
    {
        require(
            account == tokenOwner || account == ITokenRegistry(registryContract).treasury(),
            "PaymentSplitter: account is not the token owner or registry treasury"
        );
        uint96 _shares = account == tokenOwner ? _ownerShares : _totalShares - _ownerShares;
        return (totalReceived * _shares) / _totalShares - alreadyReleased;
    }
}
