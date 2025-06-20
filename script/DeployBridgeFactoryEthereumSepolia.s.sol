// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {EnvLoader} from "./EnvLoader.s.sol";
import {BridgeFactory} from "../src/BridgeFactory.sol";
import {WERC20} from "../src/WERC20.sol";

/// @title DeployBridgeFactoryEthereumSepoliaScript
/// @notice Deploys BridgeFactory and its wrapped USDC and wrapped native tokens on Ethereum Sepolia.
/// Loads deployer private key, USDC address, native wrapped token info, and relayer address from environment.
/// Grants relayer role to a specified relayer.
contract DeployBridgeFactoryEthereumSepoliaScript is EnvLoader {
    uint256 private privateKey;
    address private baseEthUsdcAddress;
    string private wrappedTokenName;
    string private wrappedTokenSymbol;
    string private wrappedNativeName;
    string private wrappedNativeSymbol;
    address private relayerAddress;
    uint8 private originalTokenDecimals;
    uint8 private ethDecimals;

    WERC20 public wrappedToken; // Wrapped USDC token
    WERC20 public wrappedNativeToken; // Wrapped native token (ETH)
    BridgeFactory public bridgeFactory;

    /// @notice Entry point for deployment script
    function run() external {
        loadEnvVars();
        vm.startBroadcast(privateKey);

        deployWrappedTokens();
        deployBridgeFactory();
        registerTokens();
        grantRelayerRole();

        logDeploymentDetails();

        vm.stopBroadcast();
    }

    /// @notice Deploys wrapped USDC and wrapped native ETH tokens
    function deployWrappedTokens() internal {
        wrappedToken = new WERC20(wrappedTokenName, wrappedTokenSymbol, originalTokenDecimals);
        wrappedNativeToken = new WERC20(wrappedNativeName, wrappedNativeSymbol, ethDecimals);
    }

    /// @notice Deploys the BridgeFactory contract
    function deployBridgeFactory() internal {
        bridgeFactory = new BridgeFactory();
    }

    /// @notice Registers wrapped USDC and native wrapped tokens in BridgeFactory
    function registerTokens() internal {
        // Register wrapped USDC token: original USDC -> wrapped USDC
        bridgeFactory.registerWrappedToken(baseEthUsdcAddress, address(wrappedToken));
        // Register wrapped native ETH token with native token key (address(0))
        bridgeFactory.registerWrappedToken(address(0), address(wrappedNativeToken));
    }

    /// @notice Grants relayer role to the relayer address
    function grantRelayerRole() internal {
        bridgeFactory.grantRelayerRole(relayerAddress);
    }

    /// @notice Logs deployed contract addresses and granted roles
    function logDeploymentDetails() internal view {
        console.log("Wrapped USDC Token deployed at:", address(wrappedToken));
        console.log("Wrapped Native ETH Token deployed at:", address(wrappedNativeToken));
        console.log("BridgeFactory deployed at:", address(bridgeFactory));
        console.log("Relayer role granted to:", relayerAddress);
    }

    /// @notice Loads required environment variables from .env file
    function loadEnvVars() internal override {
        privateKey = getEnvPrivateKey("DEPLOYER_PRIVATE_KEY");
        baseEthUsdcAddress = getEnvAddress("BASE_SEPOLIA_USDC_ADDRESS");
        wrappedTokenName = getEnvString("ETHEREUM_SEPOLIA_WRAPPED_TOKEN_NAME");
        wrappedTokenSymbol = getEnvString("ETHEREUM_SEPOLIA_WRAPPED_TOKEN_SYMBOL");
        wrappedNativeName = getEnvString("ETHEREUM_SEPOLIA_WRAPPED_NATIVE_NAME");
        wrappedNativeSymbol = getEnvString("ETHEREUM_SEPOLIA_WRAPPED_NATIVE_SYMBOL");
        originalTokenDecimals = getEnvUint("ERC20_USDC_DECIMALS");
        ethDecimals = getEnvUint("ETH_DECIMALS");
        relayerAddress = getEnvAddress("RELAYER_ADDRESS");
    }
}
