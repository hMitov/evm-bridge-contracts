// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {EnvLoader} from "./EnvLoader.s.sol";
import {BridgeFactory} from "../src/BridgeFactory.sol";
import {WERC20} from "../src/WERC20.sol";

/// @title DeployBridgeFactoryBaseSepoliaScript
/// @notice Deploys BridgeFactory, its wrapped USDC token and wrapped native ETH token on Base Sepolia testnet.
/// Loads deployer private key, USDC address, and relayer address from environment.
/// Grants relayer role to a specified relayer.
contract DeployBridgeFactoryBaseSepoliaScript is EnvLoader {
    uint256 private privateKey;
    address private ethSepoliaUsdcAddress;
    string private wrappedTokenName;
    string private wrappedTokenSymbol;
    string private wrappedNativeName;
    string private wrappedNativeSymbol;
    address private relayerAddress;
    uint8 private originalTokenDecimals;
    uint8 private ethDecimals;

    WERC20 public wrappedToken;
    WERC20 public wrappedNativeToken;
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

    /// @notice Registers wrapped USDC token and wrapped native ETH token in BridgeFactory
    function registerTokens() internal {
        // Register wrapped USDC token (original token -> wrapped token)
        bridgeFactory.registerWrappedToken(ethSepoliaUsdcAddress, address(wrappedToken));
        // Register wrapped native ETH token with native token key (address(0))
        bridgeFactory.registerWrappedToken(address(0), address(wrappedNativeToken));
    }

    /// @notice Grants relayer role to configured relayer address
    function grantRelayerRole() internal {
        bridgeFactory.grantRelayerRole(relayerAddress);
    }

    /// @notice Logs deployment information
    function logDeploymentDetails() internal view {
        console.log("Wrapped USDC Token deployed at:", address(wrappedToken));
        console.log("Wrapped Native ETH Token deployed at:", address(wrappedNativeToken));
        console.log("BridgeFactory deployed at:", address(bridgeFactory));
        console.log("Relayer role granted to:", relayerAddress);
    }

    /// @notice Loads environment variables from .env file
    function loadEnvVars() internal override {
        privateKey = getEnvPrivateKey("DEPLOYER_PRIVATE_KEY");
        ethSepoliaUsdcAddress = getEnvAddress("ETHEREUM_SEPOLIA_USDC_ADDRESS");
        wrappedTokenName = getEnvString("BASE_SEPOLIA_WRAPPED_TOKEN_NAME");
        wrappedTokenSymbol = getEnvString("BASE_SEPOLIA_WRAPPED_TOKEN_SYMBOL");
        wrappedNativeName = getEnvString("BASE_SEPOLIA_WRAPPED_NATIVE_NAME");
        wrappedNativeSymbol = getEnvString("BASE_SEPOLIA_WRAPPED_NATIVE_SYMBOL");
        originalTokenDecimals = getEnvUint("ERC20_USDC_DECIMALS");
        ethDecimals = getEnvUint("ETH_DECIMALS");
        relayerAddress = getEnvAddress("RELAYER_ADDRESS");
    }
}
