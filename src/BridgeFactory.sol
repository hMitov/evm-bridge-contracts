// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./WERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title IWERC20 Interface
/// @notice Interface for wrapped ERC20 tokens supporting bridge mint and burn operations
interface IWERC20 {
    /// @notice Mints tokens to a specified address
    /// @param to The recipient address to mint tokens to
    /// @param amount The amount of tokens to mint
    function bridgeMint(address to, uint256 amount) external;

    /// @notice Burns tokens from a specified address
    /// @param from The address to burn tokens from
    /// @param amount The amount of tokens to burn
    function bridgeBurn(address from, uint256 amount) external;
}

/// @title BridgeFactory - Cross-chain Token Bridge Contract
/// @author
/// @notice This contract facilitates locking, minting, burning, and claiming tokens across different blockchains.
/// It supports native ETH and ERC20 tokens, including permit-based transfers.
/// It uses role-based access control for security with pausing capabilities.
/// @dev Integrates OpenZeppelin's AccessControl, ReentrancyGuard, Pausable, and ECDSA utilities.
/// Bridge nonces are used to prevent replay attacks across chains.
contract BridgeFactory is AccessControl, ReentrancyGuard, Pausable {
    /// @notice Immutable chain ID of the current blockchain where this contract is deployed
    uint256 public immutable currentChainId;

    /// @notice Mapping from original tokens to their wrapped counterparts
    mapping(address => address) public wrappedTokens;

    /// @notice Mapping from wrapped tokens back to their original tokens
    mapping(address => address) public originalTokens;

    /// @notice Per-user nonce counter for generating unique operation identifiers
    mapping(address => mapping(address => uint256)) public nonces;

    /// @notice Tracks which nonces have been used for given user/token/nonce/originChain to prevent replay attacks
    mapping(address => mapping(address => mapping(uint256 => mapping(uint256 => bool)))) public usedNonces;

    /// @notice Emitted when tokens are locked for bridging
    event TokenLocked(
        address indexed user, address indexed token, uint256 amount, uint256 targetChainId, uint256 nonce
    );

    /// @notice Emitted when wrapped tokens are claimed by a user
    event TokenClaimed(address indexed user, address indexed token, uint256 amount, uint256 nonce);

    /// @notice Emitted when wrapped tokens are burned for returning to original chain
    event TokenBurned(
        address indexed user,
        address indexed wrappedToken,
        address indexed originalToken,
        uint256 amount,
        uint256 targetChainId,
        uint256 nonce
    );

    /// @notice Emitted when original tokens are released back to user
    event TokenReleased(address indexed user, address indexed token, uint256 amount);

    /// @notice Emitted when native ETH is locked for bridging
    event NativeLocked(address indexed user, uint256 amount, uint256 targetChainId, uint256 nonce);

    /// @notice Emitted when native ETH is claimed by a user on destination chain
    event NativeClaimed(address indexed user, uint256 amount, uint256 nonce);

    /// @notice Emitted when native ETH is released back to user on original chain
    event NativeReleased(address indexed user, uint256 amount);

    /// @notice Emitted on emergency withdrawal of ETH from contract by admin
    event EmergencyETHWithdrawal(address indexed to, uint256 amount);

    /// @notice Emitted when a new wrapped token mapping is registered
    event WrappedTokenRegistered(address indexed originalToken, address indexed wrappedToken);

    /// @notice Reverts if the amount is zero in operations that require positive amounts
    error ZeroAmountNotAllowed();

    /// @notice Reverts if the signature's expiration time (deadline) has passed, making the signature invalid for the operation
    error SignatureExpired();

    /// @notice Reverts if the original chain ID is zero
    error ZeroOriginalChainNotAllowed();

    /// @notice Reverts if the target chain ID is zero
    error ZeroTargetChainNotAllowed();

    /// @notice Reverts if an address parameter is zero where not allowed
    error ZeroAddressNotAllowed();

    /// @notice Reverts if a wrapped token is unregistered or unknown
    error UnregisteredWrappedToken();

    /// @notice Reverts if a claim has already been processed with the same nonce
    error ClaimAlreadyProcessed();

    /// @notice Reverts if a signature is invalid or signer lacks required role
    error InvalidSignature();

    /// @notice Reverts if an ERC20 token transfer fails
    error TokenTransferFailed();

    /// @notice Reverts if ETH transfer fails
    error EthTransferFailed();

    /// @notice Reverts if caller lacks admin privileges
    error CallerIsNotAdmin();

    /// @notice Reverts if caller lacks pauser privileges
    error CallerIsNotPauser();

    /// @notice Reverts if contract receives direct ETH transfers (not via lock functions)
    error DirectEthTransfersNotSupported();

    /// @notice Reverts if original token already registered when attempting to register wrapped token
    error OriginalTokenAlreadyRegistered();

    /// @notice Reverts if wrapped token already registered when attempting to register again
    error WrappedTokenAlreadyRegistered();

    /// @notice Reverts if original chain ID equals current chain ID (invalid bridging to same chain)
    error InvalidOriginalChain();

    /// @notice Reverts if target chain ID not equals current chain ID when claim and equals current chain ID on lock
    error InvalidTargetChain();

    /// @notice Reverts if bridge factory has smaller balance than wanted amount
    error InsufficientBalance(uint256 balance, uint256 amount);

    /// @notice Reverts when a claim attempts to use a nonce that has not been issued (i.e., nonce is greater than or equal to the current user nonce)
    error NonceNotYetAvailable();

    /// @notice Role identifier for relayer accounts authorized to sign claims
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Role identifier for admin accounts with elevated privileges
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Role identifier for accounts authorized to pause and unpause contract
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Contract constructor, grants deployer default roles and sets current chain ID
    constructor() {
        currentChainId = block.chainid;
        address deployer = msg.sender;

        _grantRole(DEFAULT_ADMIN_ROLE, deployer);
        _grantRole(ADMIN_ROLE, deployer);
        _grantRole(PAUSER_ROLE, deployer);

        _setRoleAdmin(PAUSER_ROLE, ADMIN_ROLE);
    }

    /// @notice Modifier restricting access to admin role
    modifier onlyAdmin() {
        if (!hasRole(ADMIN_ROLE, msg.sender)) revert CallerIsNotAdmin();
        _;
    }

    /// @notice Modifier restricting access to pauser role
    modifier onlyPauser() {
        if (!hasRole(PAUSER_ROLE, msg.sender)) revert CallerIsNotPauser();
        _;
    }

    /// @notice Pauses the bridge factory contract, disabling locking, claiming, and burning
    /// @dev Only callable by pauser role
    function pause() external onlyPauser {
        _pause();
    }

    /// @notice Unpauses the bridge factory contract
    /// @dev Only callable by pauser role
    function unpause() external onlyPauser {
        _unpause();
    }

    /// @notice Grants pauser role to an account
    /// @param account Address to grant pauser role
    /// @dev Only callable by admin
    function grantPauserRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        grantRole(PAUSER_ROLE, account);
    }

    /// @notice Revokes pauser role from an account
    /// @param account Address to revoke pauser role
    /// @dev Only callable by admin
    function revokePauserRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        revokeRole(PAUSER_ROLE, account);
    }

    /// @notice Grants relayer role to an account
    /// @param account Address to grant relayer role
    /// @dev Only callable by admin
    function grantRelayerRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        grantRole(RELAYER_ROLE, account);
    }

    /// @notice Revokes relayer role from an account
    /// @param account Address to revoke relayer role
    /// @dev Only callable by admin
    function revokeRelayerRole(address account) external onlyAdmin {
        if (account == address(0)) revert ZeroAddressNotAllowed();
        revokeRole(RELAYER_ROLE, account);
    }

    /// @notice Locks native ETH for bridging to another chain
    /// @param targetChainId ID of the destination chain
    /// @dev Emits NativeLocked event
    /// @dev Reverts if paused, zero amount, zero or invalid target chain ID
    function lockNative(uint256 targetChainId) external payable whenNotPaused {
        if (targetChainId == 0) revert ZeroTargetChainNotAllowed();
        if (msg.value == 0) revert ZeroAmountNotAllowed();
        if (targetChainId == currentChainId) revert InvalidTargetChain();

        uint256 userNonce = nonces[msg.sender][address(0)]++;

        emit NativeLocked(msg.sender, msg.value, targetChainId, userNonce);
    }

    /// @notice Locks ERC20 tokens for bridging to another chain
    /// @param token ERC20 token address
    /// @param amount Amount of tokens to lock
    /// @param targetChainId ID of the destination chain
    /// @dev Requires prior approval for token transfer
    /// @dev Emits TokenLocked event
    /// @dev Reverts if paused, zero amount, zero address, zero or invalid destination chain ID, or transfer failure
    function lockToken(address token, uint256 amount, uint256 targetChainId) external whenNotPaused nonReentrant {
        if (token == address(0)) revert ZeroAddressNotAllowed();
        if (amount == 0) revert ZeroAmountNotAllowed();
        if (targetChainId == 0) revert ZeroTargetChainNotAllowed();
        if (targetChainId == currentChainId) revert InvalidTargetChain();

        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (!success) revert TokenTransferFailed();

        uint256 userNonce = nonces[msg.sender][token]++;

        emit TokenLocked(msg.sender, token, amount, targetChainId, userNonce);
    }

    /// @notice Locks ERC20 tokens using permit to approve and transfer in one call
    /// @param token ERC20 token address supporting permit
    /// @param amount Amount of tokens to lock
    /// @param targetChainId ID of the destination chain
    /// @param deadline Permit signature deadline
    /// @param v Signature v parameter
    /// @param r Signature r parameter
    /// @param s Signature s parameter
    /// @dev Emits TokenLocked event
    /// @dev Reverts if paused, zero amount, zero address, zero destination chain ID, or transfer failure
    function lockTokenWithPermit(
        address token,
        uint256 amount,
        uint256 targetChainId,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused nonReentrant {
        if (token == address(0)) revert ZeroAddressNotAllowed();
        if (amount == 0) revert ZeroAmountNotAllowed();
        if (targetChainId == 0) revert ZeroTargetChainNotAllowed();
        if (targetChainId == currentChainId) revert InvalidTargetChain();

        IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
        bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
        if (!success) revert TokenTransferFailed();

        uint256 userNonce = nonces[msg.sender][token]++;

        emit TokenLocked(msg.sender, token, amount, targetChainId, userNonce);
    }

    /// @notice Claims wrapped tokens on this chain using relayer signature verification
    /// @param user Address receiving the tokens
    /// @param token Wrapped token address (address(0) if native ETH)
    /// @param amount Amount of tokens to claim
    /// @param nonce Unique nonce from orifinal chain operation
    /// @param originalChainId Chain ID where tokens were locked
    /// @param claimChainId Chain ID of the claimed tokens
    /// @param signature Relayer's signature approving the claim
    /// @dev Marks nonce as used to prevent replay
    /// @dev Emits NativeClaimed or TokenClaimed event
    /// @dev Reverts if paused, nonce already used, invalid signature, or unregistered wrapped token
    function claimWrappedWithSignature(
        address user,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 originalChainId,
        uint256 claimChainId,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (user == address(0)) revert ZeroAddressNotAllowed();
        if (amount == 0) revert ZeroAmountNotAllowed();
        if (originalChainId == 0) revert ZeroOriginalChainNotAllowed();
        if (claimChainId == 0) revert ZeroTargetChainNotAllowed();
        if (originalChainId == currentChainId) revert InvalidOriginalChain();
        if (claimChainId != currentChainId) revert InvalidTargetChain();
        if (block.timestamp > deadline) revert SignatureExpired();
        if (nonce >= nonces[user][token]) revert NonceNotYetAvailable();
        if (usedNonces[user][token][nonce][originalChainId]) revert ClaimAlreadyProcessed();

        bytes32 message = keccak256(
            abi.encodePacked(user, token, amount, nonce, originalChainId, claimChainId, address(this), deadline)
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);
        address recovered = ECDSA.recover(signedMessage, signature);

        if (!hasRole(RELAYER_ROLE, recovered)) revert InvalidSignature();

        usedNonces[user][token][nonce][originalChainId] = true;

        if (token == address(0)) {
            address wrappedNative = wrappedTokens[address(0)];
            if (wrappedNative == address(0)) revert UnregisteredWrappedToken();

            IWERC20(wrappedNative).bridgeMint(user, amount);
            emit NativeClaimed(user, amount, nonce);
        } else {
            address wrapped = wrappedTokens[token];
            if (wrapped == address(0)) revert UnregisteredWrappedToken();

            IWERC20(wrapped).bridgeMint(user, amount);
            emit TokenClaimed(user, token, amount, nonce);
        }
    }

    /// @notice Claims original tokens on this chain using relayer signature verification
    /// @param user Address receiving the tokens
    /// @param token Original token address (address(0) if native ETH)
    /// @param amount Amount of tokens to claim
    /// @param nonce Unique nonce from chain where tokens were burned
    /// @param burnChainId Chain ID where tokens were burned
    /// @param claimChainId Chain ID where tokens should be returned
    /// @param signature Relayer's signature approving the claim
    /// @dev Marks nonce as used to prevent replay
    /// @dev Emits NativeReleased or TokenReleased event
    /// @dev Reverts if paused, nonce already used, invalid signature, or token transfer failure
    function claimOriginalWithSignature(
        address user,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 burnChainId,
        uint256 claimChainId,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (user == address(0)) revert ZeroAddressNotAllowed();
        if (amount == 0) revert ZeroAmountNotAllowed();
        if (burnChainId == 0) revert ZeroOriginalChainNotAllowed();
        if (claimChainId == 0) revert ZeroTargetChainNotAllowed();
        if (claimChainId != currentChainId) revert InvalidTargetChain();
        if (block.timestamp > deadline) revert SignatureExpired();
        if (nonce >= nonces[user][token]) revert NonceNotYetAvailable();
        if (usedNonces[user][token][nonce][burnChainId]) revert ClaimAlreadyProcessed();

        bytes32 message =
            keccak256(abi.encodePacked(user, token, amount, nonce, burnChainId, claimChainId, address(this), deadline));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);
        address recovered = ECDSA.recover(signedMessage, signature);

        if (!hasRole(RELAYER_ROLE, recovered)) revert InvalidSignature();

        usedNonces[user][token][nonce][burnChainId] = true;

        if (token == address(0)) {
            _safeTransferETH(user, amount);
            emit NativeReleased(user, amount);
        } else {
            bool success = IERC20(token).transfer(user, amount);
            if (!success) revert TokenTransferFailed();
            emit TokenReleased(user, token, amount);
        }
    }

    /// @notice Burns wrapped tokens for returning original tokens on the source chain
    /// @param wrappedToken Wrapped token address
    /// @param originalToken Original token address expected on source chain
    /// @param amount Amount to burn
    /// @param originalChainId Chain ID where tokens will be returned
    /// @dev Emits TokenBurned event
    /// @dev Reverts if paused, zero addresses, zero amount, or token unregistered
    function burnWrappedForReturn(address wrappedToken, address originalToken, uint256 amount, uint256 originalChainId)
        external
        whenNotPaused
    {
        if (wrappedToken == address(0)) revert ZeroAddressNotAllowed();
        if (amount == 0) revert ZeroAmountNotAllowed();
        if (originalTokens[wrappedToken] != originalToken) revert UnregisteredWrappedToken();
        if (originalChainId == 0) revert ZeroTargetChainNotAllowed();
        if (originalChainId == currentChainId) revert InvalidTargetChain();

        IWERC20(wrappedToken).bridgeBurn(msg.sender, amount);

        uint256 userNonce = nonces[msg.sender][originalToken]++;

        emit TokenBurned(msg.sender, wrappedToken, originalToken, amount, originalChainId, userNonce);
    }

    /// @notice Registers a new mapping between original and wrapped tokens
    /// @param originalToken Address of the original token on source chain
    /// @param wrappedToken Address of the wrapped token on this chain
    /// @dev Only callable by admin
    /// @dev Reverts if zero addresses or token already registered
    /// @dev Emits WrappedTokenRegistered event
    function registerWrappedToken(address originalToken, address wrappedToken) external onlyAdmin {
        if (wrappedTokens[originalToken] != address(0)) revert OriginalTokenAlreadyRegistered();
        if (originalTokens[wrappedToken] != address(0)) revert WrappedTokenAlreadyRegistered();

        wrappedTokens[originalToken] = wrappedToken;
        originalTokens[wrappedToken] = originalToken;

        emit WrappedTokenRegistered(originalToken, wrappedToken);
    }

    /// @notice Allows admin to withdraw stuck ETH from contract in emergencies
    /// @param to Recipient address for ETH withdrawal
    /// @param amount Amount of ETH to withdraw
    /// @dev Only callable by admin
    /// @dev Reverts on zero address or zero amount
    /// @dev Emits EmergencyETHWithdrawal event
    function emergencyWithdrawETH(address to, uint256 amount) external onlyAdmin {
        if (to == address(0)) revert ZeroAddressNotAllowed();
        if (amount == 0) revert ZeroAmountNotAllowed();
        if (address(this).balance < amount) revert InsufficientBalance(address(this).balance, amount);

        payable(to).transfer(amount);

        emit EmergencyETHWithdrawal(to, amount);
    }

    /// @notice Internal safe ETH transfer helper with revert on failure
    /// @param receiver Address receiving ETH
    /// @param amount Amount of ETH to transfer
    function _safeTransferETH(address receiver, uint256 amount) internal {
        (bool success,) = receiver.call{value: amount}("");
        if (!success) revert EthTransferFailed();
    }

    /// @notice Rejects any direct ETH transfers without calling lock functions
    /// @dev Always reverts with DirectEthTransfersNotSupported error
    receive() external payable {
        revert DirectEthTransfersNotSupported();
    }

    /// @notice Rejects any direct ETH transfers without calling lock functions, fallback handler
    /// @dev Always reverts with DirectEthTransfersNotSupported error
    fallback() external payable {
        revert DirectEthTransfersNotSupported();
    }
}
