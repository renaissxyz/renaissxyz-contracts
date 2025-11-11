# Renaissxyz Contracts

A comprehensive NFT marketplace smart contract suite with gasless trading, royalty splitting, and token vending functionality built on **BNB Smart Chain (BSC)** and compatible with other EVM networks.

## Technology Stack

- **Blockchain**: BNB Smart Chain + EVM-compatible chains (X Layer)
- **Smart Contracts**: Solidity 0.8.20
- **Development**: Foundry, OpenZeppelin libraries (v4.9.0), Solady
- **Proxy Pattern**: UUPS (Universal Upgradeable Proxy Standard)
- **Standards**: ERC721, ERC2981 (Royalties), Permit2 (Uniswap)

## Supported Networks

- **BNB Smart Chain Mainnet** (Chain ID: 56)

## Contract Addresses

| Network     | RenaissRegistry                            | OrderBook                                  | TokenVendingMachine                        | RoyaltyPaymentSplitterFactory              |
| ----------- | ------------------------------------------ | ------------------------------------------ | ------------------------------------------ | ------------------------------------------ |
| BNB Mainnet | 0xF8646A3Ca093e97Bb404c3b25e675C0394DD5b30 | 0xAE3e7268EF5A062946216A44f58A8F685fFD11d0 | 0xAAb5F5FA75437a6e9E7004c12C9c56CdA4b4885A | 0x4b696E3A45F1563f5bf4dCa8c077E49087D8a890 |

## Features

- **Gasless NFT Trading**: EIP4494 permits for zero-gas NFT approvals on BNB Chain
- **Gasless Token Payments**: Permit2 integration for gasless USDC transactions
- **Automatic Royalty Splitting**: 80/20 split between creators and platform using ERC2981
- **Low-Cost NFT Minting**: Gas-efficient Proof of Integrity pattern on BNB Smart Chain
- **Decentralized Orderbook**: EIP712-based signature verification for bid/ask matching
- **Token Vending Machine**: Merkle-tree validated checkout system for pre-minted NFTs
- **Multi-Role Access Control**: Granular permissions for minters, traders, and moderators
- **Upgradeable Contracts**: UUPS proxy pattern for seamless upgrades
- **Account Safety**: Pausability and account banning for security
- **Replay Attack Protection**: Salt-based digest tracking prevents transaction replays

## Quick Start

### Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Install Dependencies

```bash
forge install OpenZeppelin/openzeppelin-contracts@v4.9.0
forge install OpenZeppelin/openzeppelin-contracts-upgradeable@v4.9.0
forge install Vectorized/solady
forge install foundry-rs/forge-std
```

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Deploy to BNB Chain

```bash
# Set environment variables
export BNB_MAINNET_RPC_URL=
export PRIVATE_KEY=your_private_key

# Deploy to BNB mainnet
forge script script/RenaissRegistry.s.sol --rpc-url $BNB_MAINNET_RPC_URL --broadcast --legacy -vvvv
```

## Core Contracts

### 1. RenaissRegistry

ERC721 NFT registry with automatic royalty management and upgradeable design.

**Key Features**:

- ERC721Enumerable for efficient token queries
- ERC2981 royalty standard support
- Automatic royalty splitter creation on mint
- Proof of Integrity pattern: `tokenId = uint256(proofOfIntegrity)`

### 2. OrderBook

Decentralized orderbook for NFT trading with gasless approvals.

**Key Features**:

- EIP712 signature-based bid/ask matching
- Permit2 integration for gasless USDC payments
- EIP4494 permits for gasless NFT approvals
- Automatic royalty distribution on trades

### 3. TokenVendingMachine

ERC20 token checkout system for purchasing pre-minted NFTs.

**Key Features**:

- Permit2-based gasless ERC20 payments
- Merkle tree validation for pack verification
- Buyback functionality for refunds
- Signature-based checkout authorization

### 4. RoyaltyPaymentSplitter & Factory

Automatic royalty distribution system using EIP-1167 minimal proxy clones.

**Key Features**:

- 80/20 split between token owner and platform
- Deterministic clone addresses (CREATE2)
- Gas-efficient EIP-1167 proxy pattern
- Batch collection for treasury payments

## Configuration

Network configurations are stored in `script/config/`:

- `bnb_mainnet.json` - BNB Smart Chain Mainnet (Chain ID: 56)

Each configuration includes:

- Network details (chainId, USDC address, Permit2 address)
- Registry settings (treasury, royalty shares, name, symbol, URI)
- Orderbook settings (tradeFeeRecipient)

## Documentation

- [script/config/](script/config/) - Network-specific configuration files
- [src/](src/) - Smart contract source code

## Security

- All contracts audited using OpenZeppelin libraries
- Role-based access control with granular permissions
- Upgradeable via UUPS pattern (admin-only)
- Pausability for emergency stops
- Reentrancy guards on critical functions
- Signature verification (EIP712, ERC1271)

## License

Business Source License 1.1
