// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title {ITokenRegistry} is an interface for a token registry.
 */
interface ITokenRegistry is IERC165 {
    /**
     * @dev mint a new token to {to}, and return the token id of the newly minted token. Upon minting a token, it is
     * required to provide the {proofOfIntegrity} of integrity of the token.
     *
     * The proof of integrity uniquely identifies the token and is used to guarantee the integrity of the token at all times.
     *
     * Use-case: for a token representing a physical asset, {proofOfIntegrity} is a hash of the information that uniquely
     * identifies the physical asset in the physical world.
     */
    function mintToken(address to, bytes32 proofOfIntegrity) external returns (uint256);

    /**
     * @dev mint a batch of new tokens to {to} if possible, and return the count of successfully minted tokens.
     */
    function mintTokenBatch(address[] calldata receivers, bytes32[] calldata proofsOfIntegrity)
        external
        returns (uint256);

    /**
     * @dev burn a token. The calling burner account or contract should be approved to manipulate the token.
     *
     * To prevent mistakes from happening, an implementation of {burnToken} should add a safeguard so that only an
     * account that is allowed to burn tokens AND is approved to maniputate the token should be able to call this
     * function.
     */
    function burnToken(bytes32 proofOfIntegrity) external returns (bool);

    /**
     * @dev burn a batch of tokens and return the number of tokens successfully burned that way.
     */
    function burnTokenBatch(bytes32[] calldata proofsOfIntegrity) external returns (uint256);

    /**
     * @notice Retrieves the token ID for a given proof of integrity
     * @dev Returns the unique token ID associated with the proof of integrity hash
     * @param proofOfIntegrity The proof of integrity hash that uniquely identifies the token
     * @return The token ID associated with the proof of integrity
     */
    function getTokenId(bytes32 proofOfIntegrity) external view returns (uint256);

    /**
     * @notice Retrieves the proof of integrity for a given token ID
     * @dev Returns the proof of integrity hash that was used when minting the token
     * @param tokenId The token ID to query
     * @return The proof of integrity hash associated with the token ID
     */
    function getTokenProofOfIntegrity(uint256 tokenId) external view returns (bytes32);

    /**
     * @notice Returns the owner of a token identified by its proof of integrity
     * @dev Provides a way to check ownership using the proof of integrity instead of token ID
     * @param tokenId The token ID to query
     * @return The address of the token owner
     */
    function ownerOf(uint256 tokenId) external view returns (address);

    /**
     * @notice Returns the address of the Renaissance treasury
     * @dev Provides a way to get the address of the Renaissance treasury
     * @return The address of the Renaissance treasury
     */
    function treasury() external view returns (address);
}
