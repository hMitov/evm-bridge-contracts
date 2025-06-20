// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

/// @title EnvLoader
/// @notice Base abstract script for loading and validating environment variables in Forge scripts
abstract contract EnvLoader is Script {
    /// @notice Error for invalid or missing environment variable with key info
    /// @param key The env variable key that is invalid or missing
    error InvalidEnvVariable(string key);

    /// @notice Error for empty environment variable with key info
    /// @param key The env variable key that is empty
    error EmptyEnvVariable(string key);

    /// @notice Error for zero address environment variable
    /// @param key The env variable key that contains zero address
    error ZeroAddressEnvVariable(string key);

    /// @notice Error for zero or invalid uint environment variable
    /// @param key The env variable key that contains invalid uint
    error InvalidUintEnvVariable(string key);

    /// @notice Abstract method to be implemented by inheriting scripts for loading .env variables
    /// @dev    Called at the beginning of the `run()` method in deployment scripts
    function loadEnvVars() internal virtual;

    /// @notice Loads private key from the .env as a uint256
    /// @param key The .env variable key
    /// @return 'The' private key as uint256
    function getEnvPrivateKey(string memory key) internal view returns (uint256) {
        try vm.envBytes32(key) returns (bytes32 keyBytes) {
            if (keyBytes == bytes32(0)) revert EmptyEnvVariable(key);
            return uint256(keyBytes);
        } catch {
            revert InvalidEnvVariable(key);
        }
    }

    /// @notice Loads address from the .env
    /// @param key The .env variable key
    /// @return 'The' parsed Ethereum address
    function getEnvAddress(string memory key) internal view returns (address) {
        try vm.envAddress(key) returns (address addr) {
            if (addr == address(0)) revert ZeroAddressEnvVariable(key);
            return addr;
        } catch {
            revert InvalidEnvVariable(key);
        }
    }

    /// @notice Loads unsigned integer from the .env
    /// @param key The .env variable key
    /// @return 'The' parsed uint8 value
    function getEnvUint(string memory key) internal view returns (uint8) {
        try vm.envUint(key) returns (uint256 val) {
            if (val == 0) revert InvalidUintEnvVariable(key);
            if (val > type(uint8).max) revert InvalidUintEnvVariable(key);
            return uint8(val);
        } catch {
            revert InvalidEnvVariable(key);
        }
    }

    /// @notice Loads non-empty string from .env
    /// @param key The .env variable key
    /// @return 'The' parsed string value
    function getEnvString(string memory key) internal view returns (string memory) {
        try vm.envString(key) returns (string memory val) {
            if (bytes(val).length == 0) revert EmptyEnvVariable(key);
            return val;
        } catch {
            revert InvalidEnvVariable(key);
        }
    }
}
