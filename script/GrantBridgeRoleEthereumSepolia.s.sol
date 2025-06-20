// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {EnvLoader} from "./EnvLoader.s.sol";
import {WERC20} from "../src/WERC20.sol";

/// @title GrantBridgeRoleEthereumSepoliaScript
/// @notice Grants the bridge role on both a wrapped token and wrapped native ETH contract to a BridgeFactory on Ethereum Sepolia.
contract GrantBridgeRoleEthereumSepoliaScript is EnvLoader {
    uint256 private privateKey;
    address payable private wrappedTokenAddress;
    address payable private wrappedEthAddress;
    address private bridgeFactoryAddress;

    /// @notice Entry point for the script
    function run() external {
        loadEnvVars();
        vm.startBroadcast(privateKey);

        grantBridgeRoles();

        vm.stopBroadcast();
    }

    /// @notice Grants the bridge role on both the wrapped token and native ETH token to the bridge factory
    function grantBridgeRoles() internal {
        WERC20 wrappedToken = WERC20(wrappedTokenAddress);
        wrappedToken.grantBridgeRole(bridgeFactoryAddress);

        WERC20 wrappedEth = WERC20(wrappedEthAddress);
        wrappedEth.grantBridgeRole(bridgeFactoryAddress);

        console.log("Granted bridge role to BridgeFactory at:", bridgeFactoryAddress);
    }

    /// @notice Loads required environment variables from .env file
    function loadEnvVars() internal override {
        privateKey = getEnvPrivateKey("DEPLOYER_PRIVATE_KEY");
        wrappedTokenAddress = payable(getEnvAddress("ETHEREUM_SEPOLIA_WRAPPED_TOKEN_ADDRESS"));
        wrappedEthAddress = payable(getEnvAddress("ETHEREUM_SEPOLIA_WRAPPED_ETH_ADDRESS"));
        bridgeFactoryAddress = getEnvAddress("ETHEREUM_SEPOLIA_BRIDGE_FACTORY_ADDRESS");
    }
}
