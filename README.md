# Cross-Chain Token Bridge System

A decentralized cross-chain token bridge for Ethereum-compatible chains, enabling users to securely lock, mint, burn, and claim tokens across multiple blockchains.

## Overview

This project implements a robust token bridging solution with the following core components:

1. **WERC20**: A wrapped ERC20 token contract with EIP-2612 permit support and role-based minting/burning, controlled by bridge operators.
2. **BridgeFactory**: The main bridge contract that manages locking tokens on source chains, minting wrapped tokens on destination chains, burning wrapped tokens, and releasing original tokens, all protected with signature verification and replay protection.

## Features

### WERC20 Contract
- ERC20 token with EIP-2612 Permit functionality
- Role-based access control (`ADMIN_ROLE`, `PAUSER_ROLE`, `BRIDGE_ROLE`)
- Bridge-controlled minting and burning
- Pause/unpause functionality for emergency control
- Prevents direct ETH transfers to the contract

### BridgeFactory Contract
- Locks native ETH and ERC20 tokens on source chains
- Supports ERC20 token locking with permit-based gas-efficient approvals
- Mints wrapped tokens on destination chains after signature verification
- Burns wrapped tokens to redeem original tokens back on source chains
- Replay protection via nonce tracking scoped by user and source chain
- Role-based access control (`ADMIN_ROLE`, `PAUSER_ROLE`, `RELAYER_ROLE`)
- Emergency withdrawal and pausing features
- Emits detailed events for off-chain relayers and monitoring

## Technical Details

### Contracts
- `WERC20.sol`: Wrapped ERC20 token implementation with permit, roles, and pausing
- `BridgeFactory.sol`: Cross-chain bridge logic managing locking, minting, burning, and claims

### Dependencies
- OpenZeppelin Contracts (ERC20Permit, AccessControl, ReentrancyGuard, Pausable, ECDSA utilities)
- Foundry for testing and deployment

## Deployment

The project uses Foundry for contract deployment on the Sepolia testnet (Ethereum Sepolia and Base Sepolia). The deployment process involves:

1. Deploying the wrapped token contract
2. Deploying the BridgeFactory contract
3. Registering the original and wrapped token pair
4. Granting the relayer role

### Deployment Commands

The `--broadcast` flag can be used with different verbosity levels:
- `-v`: Basic transaction information
- `-vv`: Transaction information and contract addresses
- `-vvv`: Transaction information, contract addresses, and function calls
- `-vvvv`: Full transaction information, contract addresses, function calls, and stack traces

#### Deploy on Base Sepolia

1. Deploy the BridgeFactory and wrapped token:
```shell
source .env
forge script script/DeployBridgeFactoryBaseSepolia.s.sol:DeployBridgeFactoryBaseSepoliaScript --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast -vvv
```

**IMPORTANT:** After deploying the BridgeFactory and WERC20 (wrapped token) contracts, you must update your `.env` file with their addresses:
- Set `BASE_SEPOLIA_BRIDGE_FACTORY_ADDRESS` to the deployed BridgeFactory address
- Set `BASE_SEPOLIA_WRAPPED_TOKEN_ADDRESS` to the deployed WERC20 address

These values are required for the GrantBridgeRole script to work correctly.

#### Deploy on Ethereum Sepolia

1. Deploy the BridgeFactory and wrapped token:
```shell
source .env
forge script script/DeployBridgeFactoryEthereumSepolia.s.sol:DeployBridgeFactoryEthereumSepoliaScript --rpc-url $ETHEREUM_SEPOLIA_RPC_URL --broadcast -vvv
```

**IMPORTANT:** After deploying the BridgeFactory and WERC20 (wrapped token) contracts, you must update your `.env` file with their addresses:
- Set `ETHEREUM_SEPOLIA_BRIDGE_FACTORY_ADDRESS` to the deployed BridgeFactory address
- Set `ETHEREUM_SEPOLIA_WRAPPED_TOKEN_ADDRESS` to the deployed WERC20 address

These values are required for the GrantBridgeRole script to work correctly.

#### Grant Bridge Role to BridgeFactory (for wrapped token)

- On Base Sepolia:
```shell
source .env
forge script script/GrantBridgeRoleBaseSepolia.s.sol:GrantBridgeRoleBaseSepoliaScript --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast -vvv
```
- On Ethereum Sepolia:
```shell
source .env
forge script script/GrantBridgeRoleEthereumSepolia.s.sol:GrantBridgeRoleEthereumSepoliaScript --rpc-url $ETHEREUM_SEPOLIA_RPC_URL --broadcast -vvv
```

Each deployment script uses Foundry's scripting capabilities to:
- Load environment variables
- Connect to the Sepolia network
- Deploy contracts with the specified parameters
- Broadcast transactions to the network
- Provide detailed transaction information

### Environment Variables

Required environment variables in `.env`:

#### Common
- `DEPLOYER_PRIVATE_KEY`: Private key for deployment (hex string, no 0x prefix)
- `RELAYER_ADDRESS`: Public address to be granted the relayer role (authorized to sign claims)

#### Token Configuration
- `ERC20_USDC_DECIMALS`: Decimals for the USDC token (e.g., 6)
- `ETH_DECIMALS`: Decimals for ETH (e.g., 18)

#### For Base Sepolia
- `BASE_SEPOLIA_RPC_URL`: RPC endpoint for Base Sepolia testnet
- `BASE_SEPOLIA_WRAPPED_TOKEN_NAME`: Name for the wrapped token deployed on Base Sepolia
- `BASE_SEPOLIA_WRAPPED_TOKEN_SYMBOL`: Symbol for the wrapped token deployed on Base Sepolia
- `BASE_SEPOLIA_WRAPPED_NATIVE_NAME`: Name for the wrapped native token deployed on Base Sepolia
- `BASE_SEPOLIA_WRAPPED_NATIVE_SYMBOL`: Symbol for the wrapped native token deployed on Base Sepolia
- `BASE_SEPOLIA_USDC_ADDRESS`: Address of the original USDC token on Base Sepolia
- `BASE_SEPOLIA_BRIDGE_FACTORY_ADDRESS`: Address of the deployed BridgeFactory contract on Base Sepolia
- `BASE_SEPOLIA_WRAPPED_TOKEN_ADDRESS`: Address of the deployed wrapped token on Base Sepolia
- `BASE_SEPOLIA_WRAPPED_ETH_ADDRESS`: Address of the deployed wrapped native token (e.g., wETH) on Base Sepolia

#### For Ethereum Sepolia
- `ETHEREUM_SEPOLIA_RPC_URL`: RPC endpoint for Ethereum Sepolia testnet
- `ETHEREUM_SEPOLIA_WRAPPED_TOKEN_NAME`: Name for the wrapped token deployed on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_WRAPPED_TOKEN_SYMBOL`: Symbol for the wrapped token deployed on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_WRAPPED_NATIVE_NAME`: Name for the wrapped native token deployed on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_WRAPPED_NATIVE_SYMBOL`: Symbol for the wrapped native token deployed on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_USDC_ADDRESS`: Address of the original USDC token on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_BRIDGE_FACTORY_ADDRESS`: Address of the deployed BridgeFactory contract on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_WRAPPED_TOKEN_ADDRESS`: Address of the deployed wrapped token on Ethereum Sepolia
- `ETHEREUM_SEPOLIA_WRAPPED_ETH_ADDRESS`: Address of the deployed wrapped native token on Ethereum Sepolia

**All variables are required and validated for non-emptiness or non-zero values by the deployment scripts.**

### Example .env
```dotenv
DEPLOYER_PRIVATE_KEY=your_private_key

# Token Configuration
ERC20_USDC_DECIMALS=6
ETH_DECIMALS=18

# Base Sepolia
BASE_SEPOLIA_RPC_URL="https://base-sepolia.gateway.tenderly.co"
BASE_SEPOLIA_WRAPPED_TOKEN_NAME="Wrapped USDC from Ethereum Sepolia"
BASE_SEPOLIA_WRAPPED_TOKEN_SYMBOL="wUSDC-S"
BASE_SEPOLIA_WRAPPED_NATIVE_NAME="Wrapped ETH from Ethereum Sepolia"
BASE_SEPOLIA_WRAPPED_NATIVE_SYMBOL="wETH-S"
BASE_SEPOLIA_USDC_ADDRESS=0x036cbd53842c5426634e7929541ec2318f3dcf7e
BASE_SEPOLIA_BRIDGE_FACTORY_ADDRESS=0xeecD8D147B9a723fb7e1b963f82DDF8Ed8aDd0e4
BASE_SEPOLIA_WRAPPED_TOKEN_ADDRESS=0x1e440D9cBe03b30Ecf091055d0295A2C9fA7ac65
BASE_SEPOLIA_WRAPPED_ETH_ADDRESS=0x0b9680E2EffAdA97FFfc6b763b7f1deE298721e16

# Ethereum Sepolia
ETHEREUM_SEPOLIA_RPC_URL="https://sepolia.gateway.tenderly.co"
ETHEREUM_SEPOLIA_WRAPPED_TOKEN_NAME="Wrapped USDC from Base Ethereum"
ETHEREUM_SEPOLIA_WRAPPED_TOKEN_SYMBOL="wUSDC-B"
ETHEREUM_SEPOLIA_WRAPPED_NATIVE_NAME="Wrapped ETH from Base Sepolia"
ETHEREUM_SEPOLIA_WRAPPED_NATIVE_SYMBOL="wETH-B"
ETHEREUM_SEPOLIA_USDC_ADDRESS=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
ETHEREUM_SEPOLIA_BRIDGE_FACTORY_ADDRESS=0x7aC56201e008f4e5b2695d14A3e1cf7C56872b0c
ETHEREUM_SEPOLIA_WRAPPED_TOKEN_ADDRESS=0x056Da8da5585376875B824F96Fa4c4008cc5565f
ETHEREUM_SEPOLIA_WRAPPED_ETH_ADDRESS=0x91f012AA63dC071d83A23b494f0023f08f0Df2a8

RELAYER_ADDRESS=0xYourRelayerAddress
```

## API Repository Updates

After deploying the contracts, update the following addresses in any API or frontend repository that interacts with the bridge:

1. **Wrapped Token Address**: Used for minting, burning, and balance queries
2. **BridgeFactory Address**: Used for locking, claiming, and event monitoring

These updates are **ESSENTIAL** for:
- Proper interaction between the API and smart contracts
- Correct bridging and claim functionality
- Real-time bridge status updates

## Testing

The project includes comprehensive tests for all contracts:

### Unit Tests
- Role management and access control
- Token minting and burning
- Pausing and unpausing
- Locking and claiming tokens (ETH and ERC20)
- Nonce replay protection
- Event emission verification
- Error handling and edge cases

### Integration Tests
- Complete bridge lifecycle (lock, mint, burn, claim, release)
- Permit-based ERC20 bridging
- Emergency withdrawal and pause scenarios
- Relayer signature validation
- Cross-chain replay protection

The integration tests verify key scenarios like signature validation, replay protection, and proper fund distribution between participants.

## Usage

### Bridging Tokens
1. Lock tokens (ETH or ERC20) on the source chain using the BridgeFactory contract
2. Relayer observes the event and submits a claim on the destination chain
3. BridgeFactory mints wrapped tokens to the user on the destination chain
4. To redeem, user burns wrapped tokens on the destination chain and claims original tokens on the source chain

### Role Management
- Only accounts with `ADMIN_ROLE` can grant/revoke `PAUSER_ROLE` and `RELAYER_ROLE`
- Only accounts with `BRIDGE_ROLE` can mint/burn tokens on WERC20
- Only accounts with `PAUSER_ROLE` can pause/unpause contracts

## Security Features
- Reentrancy protection
- Role-based access control
- Signature and replay protection
- Safe ETH and ERC20 transfers
- Emergency pause and withdrawal
- Input validation for all parameters
- Zero address checks
- Event logging for all critical actions

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:
- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools)
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network
- **Chisel**: Fast, utilitarian, and verbose solidity REPL

### Foundry Commands

#### Build
```shell
forge build
```
Compiles all contracts in the project.

#### Test
```shell
# Run all tests
forge test

# Run tests with detailed gas information
forge test --gas-report

# Run a specific test file
forge test --match-path test/unit-tests/BridgeFactory.t.sol

# Run a specific test function
forge test --match-test testLockNative

# Run tests with more verbose output
forge test -vv
```

## Documentation
- Foundry Documentation: https://book.getfoundry.sh/

## License
MIT License
