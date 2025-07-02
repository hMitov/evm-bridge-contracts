// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/BridgeFactory.sol";
import "../../src/WERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract MockERC20 is ERC20Permit {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) ERC20Permit(name) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockERC20ReturnFalse is IERC20 {
    function totalSupply() external pure override returns (uint256) {
        return 0;
    }

    function balanceOf(address) external pure override returns (uint256) {
        return 0;
    }

    function transfer(address, uint256) external pure override returns (bool) {
        return true;
    }

    function allowance(address, address) external pure override returns (uint256) {
        return type(uint256).max;
    }

    function approve(address, uint256) external pure override returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256) external pure override returns (bool) {
        return false;
    }
}

contract MockERC20TransferFalse is ERC20 {
    constructor() ERC20("MockFailToken", "MFT") {}

    function transfer(address, uint256) public pure override returns (bool) {
        return false;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract RejectEthReceiver {
    fallback() external payable {
        revert("Reject ETH");
    }
}

contract BridgeFactoryTest is Test {
    BridgeFactory bridge;
    MockERC20 token;
    MockERC20 token1;
    WERC20 wrappedToken;

    uint256 nonce = 0;
    uint256 originalChainId = 6;
    address deployer;
    address user = address(0x1234);
    address relayer = address(0x2222);
    address pauser = address(0x3333);
    address nonAdmin = address(0x5555);
    uint256 deadline = block.timestamp + 1;

    uint256 constant initialBalance = 1_000 ether;

    error EnforcedPause();
    error ECDSAInvalidSignatureLength(uint256 length);

    function setUp() public {
        deployer = address(3);

        vm.startPrank(deployer);
        bridge = new BridgeFactory();

        token = new MockERC20("Token", "USDC");
        token.mint(user, initialBalance);

        token1 = new MockERC20("Token1", "USDC1");
        token1.mint(user, initialBalance);

        wrappedToken = new WERC20("Wrapped Token", "wUSDC", 6);
        wrappedToken.grantRole(keccak256("BRIDGE_ROLE"), address(bridge));

        bridge.registerWrappedToken(address(token), address(wrappedToken));

        bridge.grantRelayerRole(relayer);
        bridge.grantPauserRole(pauser);
        vm.stopPrank();

        vm.deal(user, 10 ether);
        vm.deal(relayer, 10 ether);
        vm.deal(pauser, 10 ether);
    }

    function testOnlyAdminCanRegisterWrappedToken() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotAdmin.selector));
        bridge.registerWrappedToken(address(token), address(wrappedToken));
    }

    function testRegisterWrappedTokenRevertsDuplicate() public {
        vm.prank(deployer);
        vm.expectRevert(BridgeFactory.OriginalTokenAlreadyRegistered.selector);
        bridge.registerWrappedToken(address(token), address(wrappedToken));

        vm.prank(deployer);
        vm.expectRevert(BridgeFactory.WrappedTokenAlreadyRegistered.selector);
        bridge.registerWrappedToken(address(0x9999), address(wrappedToken));
    }

    function testFuzzRegisterWrappedToken(address original, address wrapped) public {
        vm.assume(original != address(0));
        vm.assume(wrapped != address(0));
        vm.assume(bridge.wrappedTokens(original) == address(0));
        vm.assume(bridge.originalTokens(wrapped) == address(0));

        vm.prank(deployer);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.WrappedTokenRegistered(original, wrapped);

        bridge.registerWrappedToken(original, wrapped);

        assertEq(bridge.wrappedTokens(original), wrapped);
        assertEq(bridge.originalTokens(wrapped), original);
    }

    function testGrantAndRevokeRelayerRolesSuccess() public {
        vm.prank(deployer);
        bridge.grantRelayerRole(nonAdmin);
        assertTrue(bridge.hasRole(bridge.RELAYER_ROLE(), nonAdmin));

        vm.prank(deployer);
        bridge.revokeRelayerRole(nonAdmin);
        assertFalse(bridge.hasRole(bridge.RELAYER_ROLE(), nonAdmin));
    }

    function testGrantAndRevokeRelayerRolesRevertZeroAddressProvided() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.grantRelayerRole(address(0));

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.revokeRelayerRole(address(0));
    }

    function testGrantAndRevokeRelayerRolesRevertWhenNotAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotAdmin.selector));
        bridge.grantRelayerRole(nonAdmin);

        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotAdmin.selector));
        bridge.revokeRelayerRole(nonAdmin);
    }

    function testGrantAndRevokePauserRolesSuccess() public {
        vm.prank(deployer);
        bridge.grantPauserRole(nonAdmin);
        assertTrue(bridge.hasRole(bridge.PAUSER_ROLE(), nonAdmin));

        vm.prank(deployer);
        bridge.revokePauserRole(nonAdmin);
        assertFalse(bridge.hasRole(bridge.PAUSER_ROLE(), nonAdmin));
    }

    function testGrantAndRevokePauserRolesRevertZeroAddressProvided() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.grantPauserRole(address(0));

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.revokePauserRole(address(0));
    }

    function testGrantAndRevokePauserRolesRevertWhenNotAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotAdmin.selector));
        bridge.grantPauserRole(nonAdmin);

        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotAdmin.selector));
        bridge.revokePauserRole(nonAdmin);
    }

    function testOnlyPauserCanPause() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotPauser.selector));
        bridge.pause();

        vm.prank(pauser);
        bridge.pause();
        assertTrue(bridge.paused());
    }

    function testOnlyPauserCanUnpause() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotPauser.selector));
        bridge.unpause();

        vm.prank(pauser);
        bridge.pause();
        assertTrue(bridge.paused());

        vm.prank(pauser);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function testLockNativeSuccess() public {
        vm.prank(user);
        vm.deal(user, 1 ether);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.NativeLocked(user, 1 ether, 9999, 0);
        bridge.lockNative{value: 1 ether}(9999);
    }

    function testLockNativeRevertsZeroValue() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.lockNative(9999);
    }

    function testLockNativeRevertsZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.lockNative(0);
    }

    function testLockNativeRevertsInvalidTargetChain() public {
        vm.chainId(1234);

        BridgeFactory bridgeNative = new BridgeFactory();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridgeNative.lockNative{value: 2 ether}(1234);
    }

    function testFuzzLockNative(uint256 amount, uint256 targetChainId) public {
        vm.assume(amount > 0 && amount < 10 ether);
        vm.assume(targetChainId != 0 && targetChainId != block.chainid);

        vm.deal(user, amount);
        vm.prank(user);
        uint256 expectedNonce = bridge.nonces(user, address(0));

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.NativeLocked(user, amount, targetChainId, expectedNonce);

        bridge.lockNative{value: amount}(targetChainId);
    }

    function testLockTokenTransfersSuccess() public {
        vm.startPrank(user);
        token.approve(address(bridge), 1 ether);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenLocked(user, address(token), 1 ether, 9999, 0);
        bridge.lockToken(address(token), 1 ether, 9999);
        vm.stopPrank();

        assertEq(token.balanceOf(user), initialBalance - 1 ether);
        assertEq(token.balanceOf(address(bridge)), 1 ether);
    }

    function testLockTokenRevertsZeroTokenAddress() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.lockToken(address(0), 1 ether, 0);
    }

    function testLockTokenRevertsZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.lockToken(address(token), 0, 0);
    }

    function testLockTokenRevertsZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.lockToken(address(token), 1 ether, 0);
    }

    function testLockTokenRevertsInvalidTargetChain() public {
        vm.chainId(9999);
        BridgeFactory bridgeNative = new BridgeFactory();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridgeNative.lockToken(address(token), 1 ether, 9999);
    }

    function testLockTokenRevertsIfNotApproved() public {
        vm.prank(user);
        vm.expectRevert();
        bridge.lockToken(address(token), 1 ether, 9999);
    }

    function testLockTokenTransferFromReturnsFalse() public {
        MockERC20ReturnFalse tokenFalse = new MockERC20ReturnFalse();

        vm.prank(user);
        vm.expectRevert(BridgeFactory.TokenTransferFailed.selector);
        bridge.lockToken(address(tokenFalse), 1 ether, 9999);
    }

    function testFuzzLockToken(uint256 amount, uint256 targetChainId) public {
        vm.assume(amount > 0 && amount < initialBalance);
        vm.assume(targetChainId != 0 && targetChainId != block.chainid);

        vm.startPrank(user);
        uint256 expectedNonce = bridge.nonces(user, address(token));
        token.approve(address(bridge), amount);

        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenLocked(user, address(token), amount, targetChainId, expectedNonce);

        bridge.lockToken(address(token), amount, targetChainId);
        vm.stopPrank();

        assertEq(token.balanceOf(user), initialBalance - amount);
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    function testLockTokenWithPermitSuccess() public {
        (address user1, uint256 userPrivateKey) = makeAddrAndKey("user1");

        MockERC20 tokenWithPermit = new MockERC20("TokenPermit", "TP");
        tokenWithPermit.mint(user1, 10 ether);

        vm.startPrank(user1);

        bytes32 DOMAIN_SEPARATOR = tokenWithPermit.DOMAIN_SEPARATOR();
        uint256 nonce1 = tokenWithPermit.nonces(user1);
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                user1,
                address(bridge),
                1 ether,
                nonce1,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);

        bridge.lockTokenWithPermit(address(tokenWithPermit), 1 ether, 9999, deadline, v, r, s);

        vm.stopPrank();

        assertEq(tokenWithPermit.balanceOf(user1), 10 ether - 1 ether);
        assertEq(tokenWithPermit.balanceOf(address(bridge)), 1 ether);
    }

    function testLockTokenWithPermitRevertsZeroAddress() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.lockTokenWithPermit(address(0), 1 ether, 9999, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testLockTokenWithPermitRevertsZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.lockTokenWithPermit(address(token), 0, 9999, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testLockTokenWithPermitRevertsZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.lockTokenWithPermit(address(token), 1 ether, 0, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testLockTokenWithPermitRevertsInvalidTargetChain() public {
        vm.chainId(9999);

        BridgeFactory bridgeToken = new BridgeFactory();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridgeToken.lockTokenWithPermit(address(token), 1 ether, 9999, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testClaimWrappedWithSignatureRevertsEmptySignature() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert();
        bridge.claimWrappedWithSignature(
            user, address(token), 1 ether, nonce, originalChainId, claimChainId, deadline, ""
        );
    }

    function testClaimWrappedWithSignatureRevertsTooShortSignature() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert();
        bridge.claimWrappedWithSignature(
            user, address(token), 1 ether, nonce, originalChainId, claimChainId, deadline, hex"1234"
        );
    }

    function testClaimWrappedWithSignatureRevertZeroUser() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.claimWrappedWithSignature(
            address(0), address(token), 1 ether, nonce, originalChainId, claimChainId, deadline, hex""
        );
    }

    function testClaimWrappedWithSignatureRevertZeroAmount() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.claimWrappedWithSignature(user, address(token), 0, nonce, originalChainId, claimChainId, deadline, hex"");
    }

    function testClaimWrappedWithSignatureRevertZeroOriginalChain() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroOriginalChainNotAllowed.selector));
        bridge.claimWrappedWithSignature(user, address(token), 1 ether, nonce, 0, claimChainId, deadline, hex"");
    }

    function testClaimWrappedWithSignatureRevertZeroClaimChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.claimWrappedWithSignature(user, address(token), 1 ether, nonce, 3, 0, deadline, hex"");
    }

    function testClaimWrappedWithSignatureRevertOriginalChainIsCurrentChain() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidOriginalChain.selector));
        bridge.claimWrappedWithSignature(
            user, address(token), 1 ether, nonce, block.chainid, claimChainId, deadline, hex""
        );
    }

    function testClaimWrappedWithSignatureRevertClaimChainIsNotCurrentChain() public {
        uint256 claimChainId = 5;

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.claimWrappedWithSignature(
            user, address(token), 1 ether, nonce, originalChainId, claimChainId, deadline, hex""
        );
    }

    function testClaimWrappedWithSignatureRevertSignatureExpired() public {
        uint256 claimChainId = 9999;
        vm.chainId(claimChainId);

        BridgeFactory bridge1 = new BridgeFactory();

        uint256 currentTime = block.timestamp;

        vm.warp(currentTime + 1000);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.SignatureExpired.selector));

        bridge1.claimWrappedWithSignature(
            user, address(token), 1 ether, nonce, originalChainId, claimChainId, currentTime, hex""
        );
    }

    function testClaimWrappedWithSignatureRevertNonceAlreadyUsed() public {
        testLockTokenTransfersSuccess();
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        bytes32 message = keccak256(
            abi.encodePacked(
                user, address(token), amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        bridge.claimWrappedWithSignature(
            user, address(token), amount, nonce, originalChainId, block.chainid, deadline, signature
        );

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ClaimAlreadyProcessed.selector));
        bridge.claimWrappedWithSignature(
            user, address(token), amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimWrappedWithSignatureRevertInvalidSignerRole() public {
        testLockTokenTransfersSuccess();
        uint256 fakeRelayerKey = 0x1234;

        uint256 amount = 1 ether;

        bytes32 message = keccak256(
            abi.encode(user, address(token), amount, nonce, originalChainId, block.chainid, address(bridge), deadline)
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeRelayerKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidSignature.selector));
        bridge.claimWrappedWithSignature(
            user, address(token), amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimWrappedWithSignatureTokenRevertInvalidWrappedToken() public {
        vm.startPrank(user);
        token1.approve(address(bridge), 1 ether);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenLocked(user, address(token1), 1 ether, 9999, 0);
        bridge.lockToken(address(token1), 1 ether, 9999);
        vm.stopPrank();

        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;

        bytes32 message = keccak256(
            abi.encodePacked(
                user, address(token1), amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.claimWrappedWithSignature(
            user, address(token1), amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimWrappedWithSignatureRevertUnregisteredWrappedTokenNative() public {
        testLockNativeSuccess();
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        address nativeToken = address(0);

        bytes32 message = keccak256(
            abi.encodePacked(
                user, nativeToken, amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.claimWrappedWithSignature(
            user, nativeToken, amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimWrappedWithSignatureRevertUnregisteredWrappedToken() public {
        testLockNativeSuccess();
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        address nativeToken = address(0);

        bytes32 message = keccak256(
            abi.encodePacked(
                user, nativeToken, amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.claimWrappedWithSignature(
            user, nativeToken, amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimWrappedWithSignatureWhenNativeSuccess() public {
        testLockNativeSuccess();
        uint256 amount = 1 ether;
        address tokenZero = address(0);
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.startPrank(deployer);

        WERC20 newWrappedNative = new WERC20("Wrapped Native", "wETH", 18);

        newWrappedNative.grantRole(keccak256("BRIDGE_ROLE"), address(bridge));

        bridge.registerWrappedToken(tokenZero, address(newWrappedNative));

        bridge.grantRelayerRole(relayerAddr);

        vm.stopPrank();

        vm.deal(address(bridge), amount);

        bytes32 message = keccak256(
            abi.encodePacked(user, tokenZero, amount, nonce, originalChainId, block.chainid, address(bridge), deadline)
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);

        vm.prank(user);
        bridge.claimWrappedWithSignature(
            user, tokenZero, amount, nonce, originalChainId, block.chainid, deadline, abi.encodePacked(r, s, v)
        );

        bool used = bridge.usedNonces(user, tokenZero, nonce, originalChainId);
        assertTrue(used);
    }

    function testClaimWrappedWithSignatureFailsInvalidSignature() public {
        testLockNativeSuccess();
        uint256 amount = 1 ether;
        address zeroToken = address(0);

        bytes memory invalidSig = hex"aaaaaaaa";

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ECDSAInvalidSignatureLength.selector, 4));
        bridge.claimWrappedWithSignature(
            user, zeroToken, amount, nonce, originalChainId, block.chainid, deadline, invalidSig
        );
    }

    function testClaimOriginalWithSignatureRevertZeroUser() public {
        testLockTokenTransfersSuccess();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.claimOriginalWithSignature(
            address(0), address(token), 1 ether, nonce, originalChainId, block.chainid, deadline, hex""
        );
    }

    function testClaimOriginalWithSignatureRevertZeroAmount() public {
        testLockTokenTransfersSuccess();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.claimOriginalWithSignature(
            user, address(token), 0, nonce, originalChainId, block.chainid, deadline, hex""
        );
    }

    function testClaimOriginalWithSignatureRevertZeroBurnChain() public {
        testLockTokenTransfersSuccess();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroOriginalChainNotAllowed.selector));
        bridge.claimOriginalWithSignature(user, address(token), 1 ether, nonce, 0, block.chainid, deadline, hex"");
    }

    function testClaimOriginalWithSignatureRevertZeroClaimChain() public {
        testLockTokenTransfersSuccess();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.claimOriginalWithSignature(user, address(token), 1 ether, nonce, originalChainId, 0, deadline, hex"");
    }

    function testClaimOriginalWithSignatureRevertTargetChainIsNotCurrentChain() public {
        testLockTokenTransfersSuccess();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.claimOriginalWithSignature(user, address(token), 1 ether, nonce, originalChainId, 5, deadline, hex"");
    }

    function testClaimOriginalWithSignatureRevertSignatureExpired() public {
        testLockTokenTransfersSuccess();
        uint256 claimChainId = 9999;
        vm.chainId(claimChainId);

        BridgeFactory bridge1 = new BridgeFactory();

        uint256 currentTime = block.timestamp;

        vm.warp(currentTime + 1000);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.SignatureExpired.selector));
        bridge1.claimOriginalWithSignature(
            user, address(token), 1 ether, nonce, originalChainId, claimChainId, currentTime, hex""
        );
    }

    function testClaimOriginalWithSignatureRevertNonceAlreadyUsed() public {
        testLockTokenTransfersSuccess();
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;

        bytes32 message = keccak256(
            abi.encodePacked(
                user, address(token), amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        token.mint(address(bridge), amount);

        vm.prank(user);
        bridge.claimOriginalWithSignature(
            user, address(token), amount, nonce, originalChainId, block.chainid, deadline, signature
        );

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ClaimAlreadyProcessed.selector));
        bridge.claimOriginalWithSignature(
            user, address(token), amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimOriginalWithSignatureRevertInvalidSignerRole() public {
        testLockTokenTransfersSuccess();
        (, uint256 fakePrivateKey) = makeAddrAndKey("faker");
        uint256 amount = 1 ether;
        bytes32 message = keccak256(
            abi.encodePacked(
                user, address(token), amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakePrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidSignature.selector));
        bridge.claimOriginalWithSignature(
            user, address(token), amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testClaimOriginalWithSignatureNativeSuccess() public {
        testLockNativeSuccess();
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        address tokenZero = address(0);

        vm.deal(address(bridge), amount);

        bytes32 message = keccak256(
            abi.encodePacked(user, tokenZero, amount, nonce, originalChainId, block.chainid, address(bridge), deadline)
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.NativeReleased(user, amount);

        bridge.claimOriginalWithSignature(
            user, tokenZero, amount, nonce, originalChainId, block.chainid, deadline, signature
        );

        assertTrue(bridge.usedNonces(user, tokenZero, nonce, originalChainId));
    }

    function testClaimWrappedWithSignatureRevertECDSAInvalidSignatureLength() public {
        testLockTokenTransfersSuccess();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ECDSAInvalidSignatureLength.selector, 4));
        bridge.claimWrappedWithSignature(
            user, address(token), 1 ether, nonce, originalChainId, block.chainid, deadline, hex"aaaaaaaa"
        );
    }

    function testClaimOriginalWithSignatureTokenSuccess() public {
        uint256 amount = 1 ether;
        uint256 balanceBefore = token1.balanceOf(user);

        vm.startPrank(user);
        token1.approve(address(bridge), amount);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenLocked(user, address(token1), amount, 9999, 0);
        bridge.lockToken(address(token1), amount, 9999);
        vm.stopPrank();

        uint256 balanceAfterLock = token1.balanceOf(user);
        assertEq(balanceBefore - balanceAfterLock, amount);

        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");
        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        bytes32 message = keccak256(
            abi.encodePacked(
                user, address(token1), amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenReleased(user, address(token1), amount);
        bridge.claimOriginalWithSignature(
            user, address(token1), amount, nonce, originalChainId, block.chainid, deadline, signature
        );

        uint256 balanceAfterClaim = token1.balanceOf(user);
        assertEq(balanceAfterClaim, balanceBefore);

        bool used = bridge.usedNonces(user, address(token1), nonce, originalChainId);
        assertTrue(used);
    }

    function testClaimOriginalWithSignatureEthTransferFails() public {
        RejectEthReceiver badReceiver = new RejectEthReceiver();
        vm.prank(address(badReceiver));
        vm.deal(address(badReceiver), 1 ether);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.NativeLocked(address(badReceiver), 1 ether, 9999, 0);
        bridge.lockNative{value: 1 ether}(9999);

        (address relayerAddr, uint256 relayerKey) = makeAddrAndKey("relayer");
        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        bytes32 message = keccak256(
            abi.encodePacked(
                badReceiver, address(0), amount, nonce, originalChainId, block.chainid, address(bridge), deadline
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(badReceiver));
        vm.expectRevert(BridgeFactory.EthTransferFailed.selector);
        bridge.claimOriginalWithSignature(
            address(badReceiver), address(0), amount, nonce, originalChainId, block.chainid, deadline, signature
        );
    }

    function testBurnWrappedForReturnRevertZeroAddress() public {
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.burnWrappedForReturn(address(0), address(token), 1 ether, originalChainId);
        vm.stopPrank();
    }

    function testBurnWrappedForReturnRevertZeroAmount() public {
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 0, originalChainId);
        vm.stopPrank();
    }

    function testBurnWrappedForReturnRevertUnregisteredWrappedToken() public {
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.burnWrappedForReturn(address(0x9999), address(token), 1 ether, originalChainId);
        vm.stopPrank();
    }

    function testBurnWrappedForReturnRevertZeroOriginalChainId() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 1 ether, 0);
    }

    function testBurnWrappedForReturnRevertOriginalChainIsCurrentChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 1 ether, block.chainid);
    }

    function testBurnWrappedForReturnEmitsEvent() public {
        vm.startPrank(address(bridge));

        wrappedToken.bridgeMint(user, 10 ether);

        vm.stopPrank();

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit BridgeFactory.TokenBurned(user, address(wrappedToken), address(token), 10 ether, originalChainId, 0);
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 10 ether, originalChainId);
        vm.stopPrank();

        assertEq(wrappedToken.balanceOf(user), 0);
    }

    function testEmergencyWithdrawETHRevertZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(BridgeFactory.ZeroAddressNotAllowed.selector);
        bridge.emergencyWithdrawETH(address(0), 1 ether);
    }

    function testEmergencyWithdrawETHRevertZeroAmount() public {
        vm.prank(deployer);
        vm.expectRevert(BridgeFactory.ZeroAmountNotAllowed.selector);
        bridge.emergencyWithdrawETH(address(user), 0);
    }

    function testEmergencyWithdrawETHRevertInsufficientBalance() public {
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeFactory.InsufficientBalance.selector, address(bridge).balance, 1 ether)
        );
        bridge.emergencyWithdrawETH(user, 1 ether);
    }

    function testEmergencyWithdrawETHSuccess() public {
        vm.deal(address(bridge), 1 ether);

        uint256 balanceBefore = user.balance;

        vm.prank(deployer);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.EmergencyETHWithdrawal(user, 1 ether);

        bridge.emergencyWithdrawETH(user, 1 ether);

        uint256 balanceAfter = user.balance;

        assertEq(balanceAfter - balanceBefore, 1 ether);
    }

    function testEmergencyWithdrawETHRevertsForNonAdmin() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.CallerIsNotAdmin.selector));
        bridge.emergencyWithdrawETH(user, 1 ether);
    }

    function testRejectDirectETHTransferToReceive() public {
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.DirectEthTransfersNotSupported.selector));
        payable(address(bridge)).transfer(1 ether);
    }

    function testRejectDirectETHTransferToFallback() public {
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.DirectEthTransfersNotSupported.selector));
        (bool success,) = address(bridge).call{value: 1 ether}(abi.encodePacked(bytes4(0x12345678)));
        assertTrue(success);
    }

    function testReplayAttackDifferentAddressesRevertInvalidSignature() public {
        vm.startPrank(deployer);
        vm.chainId(1);
        BridgeFactory bridgeChain1 = new BridgeFactory();

        vm.chainId(2);
        BridgeFactory bridgeChain2 = new BridgeFactory();
        vm.stopPrank();

        vm.startPrank(user);
        vm.deal(user, 2 ether);
        bridgeChain1.lockNative{value: 1 ether}(2);
        bridgeChain2.lockNative{value: 1 ether}(1);
        vm.stopPrank();

        uint256 amount = 1 ether;
        address tokenZero = address(0);
        (address relayerAddress, uint256 relayerKey) = makeAddrAndKey("relayer");
        address bridgeChain1Address = address(bridgeChain1);
        address bridgeChain2Address = address(bridgeChain2);

        registerAndGrantRoles(bridgeChain1Address, tokenZero, relayerAddress);
        registerAndGrantRoles(bridgeChain2Address, tokenZero, relayerAddress);

        vm.deal(bridgeChain1Address, amount);
        vm.deal(bridgeChain2Address, amount);

        bytes memory signature = signClaimMessage(
            user, tokenZero, amount, nonce, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );

        makeClaim(bridgeChain1Address, user, tokenZero, amount, nonce, originalChainId, 1, deadline, signature);

        vm.expectRevert(BridgeFactory.InvalidSignature.selector);
        makeClaim(bridgeChain2Address, user, tokenZero, amount, nonce, originalChainId, 2, deadline, signature);
    }

    function testClaimWrappedWithSignatureRevertSignatureExpiration() public {
        vm.startPrank(deployer);
        vm.chainId(1);
        BridgeFactory bridgeChain1 = new BridgeFactory();
        vm.stopPrank();

        vm.startPrank(user);
        vm.deal(user, 1 ether);
        bridgeChain1.lockNative{value: 1 ether}(2);
        vm.stopPrank();

        uint256 amount = 1 ether;
        address tokenZero = address(0);
        (address relayerAddress, uint256 relayerKey) = makeAddrAndKey("relayer");
        address bridgeChain1Address = address(bridgeChain1);

        registerAndGrantRoles(bridgeChain1Address, tokenZero, relayerAddress);
        vm.deal(bridgeChain1Address, amount);

        bytes memory signature = signClaimMessage(
            user, tokenZero, amount, nonce, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );

        makeClaim(bridgeChain1Address, user, tokenZero, amount, nonce, originalChainId, 1, deadline, signature);
        assertTrue(bridgeChain1.usedNonces(user, tokenZero, nonce, originalChainId));

        uint256 newNonce = nonce + 1;
        bytes memory signatureNewNonce = signClaimMessage(
            user, tokenZero, amount, newNonce, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );

        vm.warp(block.timestamp + 365 days);

        vm.expectRevert(BridgeFactory.SignatureExpired.selector);
        makeClaim(
            bridgeChain1Address, user, tokenZero, amount, newNonce, originalChainId, 1, deadline, signatureNewNonce
        );
    }

    function testClaimWrappedWithSignatureNotBurnNonce() public {
        vm.startPrank(deployer);
        vm.chainId(1);
        BridgeFactory bridgeChain1 = new BridgeFactory();
        vm.stopPrank();

        vm.startPrank(user);
        vm.deal(user, 1 ether);
        bridgeChain1.lockNative{value: 1 ether}(2);
        vm.stopPrank();

        uint256 amount = 1 ether;
        address tokenZero = address(0);
        (address relayerAddress, uint256 relayerKey) = makeAddrAndKey("relayer");
        address bridgeChain1Address = address(bridgeChain1);

        registerAndGrantRoles(bridgeChain1Address, tokenZero, relayerAddress);
        vm.deal(bridgeChain1Address, amount);

        uint256 skippedNonce = 5;
        bytes memory sig = signClaimMessage(
            user, tokenZero, amount, nonce, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );

        vm.prank(user);
        vm.expectRevert(BridgeFactory.InvalidSignature.selector);
        bridgeChain1.claimWrappedWithSignature(user, tokenZero, amount, skippedNonce, originalChainId, 1, deadline, sig);
    }

    function testClaimWrappedWithSignatureWithNonceIncrementMechanism() public {
        vm.startPrank(deployer);
        vm.chainId(1);
        BridgeFactory bridgeChain1 = new BridgeFactory();
        vm.stopPrank();

        vm.startPrank(user);
        vm.deal(user, 1 ether);
        bridgeChain1.lockNative{value: 1 ether}(2);
        vm.stopPrank();

        uint256 amount = 1 ether;
        address tokenZero = address(0);
        (address relayerAddress, uint256 relayerKey) = makeAddrAndKey("relayer");
        address bridgeChain1Address = address(bridgeChain1);

        registerAndGrantRoles(bridgeChain1Address, tokenZero, relayerAddress);
        vm.deal(bridgeChain1Address, amount);

        uint256 nonce0 = 0;
        bytes memory sig1 = signClaimMessage(
            user, tokenZero, amount, nonce0, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );
        vm.prank(user);
        bridgeChain1.claimWrappedWithSignature(user, tokenZero, amount, nonce0, originalChainId, 1, deadline, sig1);

        bool used0 = bridgeChain1.usedNonces(user, tokenZero, nonce0, originalChainId);
        assertTrue(used0);

        vm.startPrank(user);
        vm.deal(user, 1 ether);
        bridgeChain1.lockNative{value: 1 ether}(2);
        vm.stopPrank();

        uint256 nonce1 = 1;
        bytes memory sig3 = signClaimMessage(
            user, tokenZero, amount, nonce1, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );
        vm.prank(user);
        bridgeChain1.claimWrappedWithSignature(user, tokenZero, amount, nonce1, originalChainId, 1, deadline, sig3);

        bool used1 = bridgeChain1.usedNonces(user, tokenZero, nonce1, originalChainId);
        assertTrue(used1);
    }

    function testGlobalNonceNoCollisionAcrossTokens() public {
        vm.startPrank(deployer);
        vm.chainId(1);
        BridgeFactory bridgeChain1 = new BridgeFactory();
        vm.stopPrank();

        uint256 amount = 1 ether;
        (address relayerAddress, uint256 relayerKey) = makeAddrAndKey("relayer");
        address bridgeChain1Address = address(bridgeChain1);

        MockERC20 tokenA = new MockERC20("TokenA", "TKA");
        MockERC20 tokenB = new MockERC20("TokenB", "TKB");

        registerAndGrantRoles(bridgeChain1Address, address(tokenA), relayerAddress);
        registerAndGrantRoles(bridgeChain1Address, address(tokenB), relayerAddress);

        vm.deal(bridgeChain1Address, amount);

        tokenA.mint(user, amount);
        vm.startPrank(user);
        tokenA.approve(bridgeChain1Address, amount);
        bridgeChain1.lockToken(address(tokenA), amount, 2);
        vm.stopPrank();

        tokenB.mint(user, amount);
        vm.startPrank(user);
        tokenB.approve(bridgeChain1Address, amount);
        bridgeChain1.lockToken(address(tokenB), amount, 2);
        vm.stopPrank();

        bytes memory sigTokenA = signClaimMessage(
            user, address(tokenA), amount, 0, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );
        vm.prank(user);
        bridgeChain1.claimWrappedWithSignature(
            user, address(tokenA), amount, 0, originalChainId, 1, deadline, sigTokenA
        );

        bytes memory sigTokenB = signClaimMessage(
            user, address(tokenB), amount, 0, originalChainId, 1, bridgeChain1Address, relayerKey, deadline
        );
        vm.prank(user);
        bridgeChain1.claimWrappedWithSignature(
            user, address(tokenB), amount, 0, originalChainId, 1, deadline, sigTokenB
        );

        uint256 nonceTokenA = bridgeChain1.nonces(user, address(tokenA));
        uint256 nonceTokenB = bridgeChain1.nonces(user, address(tokenB));

        assertEq(nonceTokenA, nonceTokenB);
    }

    function registerAndGrantRoles(address bridgeFactory_, address token_, address relayer_) internal {
        WERC20 newWrappedNative = new WERC20("Wrapped Native", "wETH", 18);
        BridgeFactory bridgeFactory = BridgeFactory(payable(bridgeFactory_));
        newWrappedNative.grantRole(keccak256("BRIDGE_ROLE"), address(bridgeFactory));

        vm.startPrank(deployer);
        bridgeFactory.registerWrappedToken(token_, address(newWrappedNative));
        bridgeFactory.grantRelayerRole(relayer_);
        vm.stopPrank();
    }

    function signClaimMessage(
        address user_,
        address token_,
        uint256 amount_,
        uint256 nonce_,
        uint256 originalChainId_,
        uint256 targetChainId_,
        address bridgeAddress_,
        uint256 relayerPrivateKey_,
        uint256 deadline_
    ) internal pure returns (bytes memory) {
        bytes32 message = keccak256(
            abi.encodePacked(
                user_, token_, amount_, nonce_, originalChainId_, targetChainId_, bridgeAddress_, deadline_
            )
        );
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey_, signedMessage);
        return abi.encodePacked(r, s, v);
    }

    function makeClaim(
        address bridgeFactoryAddress,
        address user_,
        address token_,
        uint256 amount_,
        uint256 nonce_,
        uint256 originalChainId_,
        uint256 claimChainId,
        uint256 deadline_,
        bytes memory signature
    ) internal {
        vm.prank(user_);
        BridgeFactory(payable(bridgeFactoryAddress)).claimWrappedWithSignature(
            user_, token_, amount_, nonce_, originalChainId_, claimChainId, deadline_, signature
        );
    }
}
