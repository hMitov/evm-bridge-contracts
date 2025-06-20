// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Wrapped ERC20 Token with Bridge Role, Pause, and Access Control
/// @notice ERC20 token with permit, bridge minting/burning and role-based access control
/// @dev Inherits OpenZeppelin's ERC20Permit, AccessControl, ReentrancyGuard, and Pausable.
/// Implements minting and burning restricted to bridge role with pause functionality.
contract WERC20 is ERC20Permit, AccessControl, ReentrancyGuard, Pausable {
    /// @notice Immutable storage of token decimals
    uint8 private immutable decimalsValue;

    /// @notice Error for empty string input in constructor
    error EmptyStringNotAllowed();

    /// @notice Error for zero address inputs in role management functions
    error ZeroAddressNotAllowed();

    /// @notice Error for zero amount inputs in mint/burn functions
    error ZeroAmountNotAllowed();

    /// @notice Error when contract receives ETH directly via fallback/receive
    error DirectEthTransfersNotSupported();

    /// @notice Error when caller lacks admin role required for certain functions
    error CallerIsNotAdmin();

    /// @notice Error when caller lacks pauser role required for pause/unpause functions
    error CallerIsNotPauser();

    /// @notice Error when caller lacks bridge role required for minting/burning
    error CallerIsNotBridger();

    /// @notice Role identifier for administrator accounts
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Role identifier for accounts authorized to pause and unpause the contract
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Role identifier for accounts authorized to mint and burn tokens via bridge operations
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");

    /// @notice Constructs the wrapped token contract with a name, symbol, and decimals
    /// @param _name The name of the ERC20 token
    /// @param _symbol The symbol of the ERC20 token
    /// @param _decimals The number of decimals for the token (non-zero)
    /// @dev Grants deployer all roles (admin, pauser, bridger)
    constructor(string memory _name, string memory _symbol, uint8 _decimals) ERC20(_name, _symbol) ERC20Permit(_name) {
        if (bytes(_name).length == 0) revert EmptyStringNotAllowed();
        if (bytes(_symbol).length == 0) revert EmptyStringNotAllowed();
        if (_decimals == 0) revert ZeroAmountNotAllowed();

        decimalsValue = _decimals;

        address deployer = msg.sender;

        _grantRole(DEFAULT_ADMIN_ROLE, deployer);
        _grantRole(ADMIN_ROLE, deployer);
        _grantRole(PAUSER_ROLE, deployer);

        _setRoleAdmin(PAUSER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(BRIDGE_ROLE, ADMIN_ROLE);
    }

    /// @notice Modifier that restricts function access to admins only
    /// @dev Reverts with CallerIsNotAdmin if caller lacks ADMIN_ROLE
    modifier onlyAdmin() {
        if (!hasRole(ADMIN_ROLE, msg.sender)) revert CallerIsNotAdmin();
        _;
    }

    /// @notice Modifier that restricts function access to pausers only
    /// @dev Reverts with CallerIsNotPauser if caller lacks PAUSER_ROLE
    modifier onlyPauser() {
        if (!hasRole(PAUSER_ROLE, msg.sender)) revert CallerIsNotPauser();
        _;
    }

    /// @notice Modifier that restricts function access to bridgers only
    /// @dev Reverts with "No bridger role mtf" if caller lacks BRIDGE_ROLE
    modifier onlyBridger() {
        if (!hasRole(BRIDGE_ROLE, msg.sender)) revert CallerIsNotBridger();
        _;
    }

    /// @notice Pauses all token minting and burning operations
    /// @dev Only callable by accounts with PAUSER_ROLE
    function pause() external onlyPauser {
        _pause();
    }

    /// @notice Unpauses the contract, enabling minting and burning operations
    /// @dev Only callable by accounts with PAUSER_ROLE
    function unpause() external onlyPauser {
        _unpause();
    }

    /// @notice Grants the PAUSER_ROLE to an account
    /// @param account The address to grant the pauser role to
    /// @dev Only callable by ADMIN_ROLE; reverts if zero address provided
    function grantPauserRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        grantRole(PAUSER_ROLE, account);
    }

    /// @notice Revokes the PAUSER_ROLE from an account
    /// @param account The address to revoke the pauser role from
    /// @dev Only callable by ADMIN_ROLE; reverts if zero address provided
    function revokePauserRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        revokeRole(PAUSER_ROLE, account);
    }

    /// @notice Grants the BRIDGE_ROLE to an account
    /// @param account The address to grant the bridge role to
    /// @dev Only callable by ADMIN_ROLE; reverts if zero address provided
    function grantBridgeRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        grantRole(BRIDGE_ROLE, account);
    }

    /// @notice Revokes the BRIDGE_ROLE from an account
    /// @param account The address to revoke the bridge role from
    /// @dev Only callable by ADMIN_ROLE; reverts if zero address provided
    function revokeBridgeRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        revokeRole(BRIDGE_ROLE, account);
    }

    // Override decimals() function
    function decimals() public view virtual override returns (uint8) {
        return decimalsValue;
    }

    /// @notice Mints tokens to a specified address
    /// @param to The recipient address of minted tokens
    /// @param amount The amount of tokens to mint (must be > 0)
    /// @dev Only callable by accounts with BRIDGE_ROLE and when contract is not paused
    /// @dev Reverts if `amount` is zero
    function bridgeMint(address to, uint256 amount) external onlyBridger whenNotPaused {
        if (amount == 0) revert ZeroAmountNotAllowed();
        _mint(to, amount);
    }

    /// @notice Burns tokens from a specified address
    /// @param from The address whose tokens will be burned
    /// @param amount The amount of tokens to burn (must be > 0)
    /// @dev Only callable by accounts with BRIDGE_ROLE and when contract is not paused
    /// @dev Reverts if `amount` is zero
    function bridgeBurn(address from, uint256 amount) external onlyBridger whenNotPaused {
        if (amount == 0) revert ZeroAmountNotAllowed();
        _burn(from, amount);
    }

    /// @notice Rejects direct ETH transfers to contract
    /// @dev Reverts with DirectEthTransfersNotSupported error
    receive() external payable {
        revert DirectEthTransfersNotSupported();
    }

    /// @notice Rejects direct ETH transfers to contract with calldata
    /// @dev Reverts with DirectEthTransfersNotSupported error
    fallback() external payable {
        revert DirectEthTransfersNotSupported();
    }
}
