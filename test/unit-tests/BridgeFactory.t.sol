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

contract MockRevertingTransferFromToken {
    error TokenTransferFailed();

    function transfer(address, uint256) external pure returns (bool) {
        revert TokenTransferFailed();
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        revert TokenTransferFailed();
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
    WERC20 wrappedToken;

    uint256 nonce = 5;
    uint256 sourceChainId = 6;
    address deployer;
    address user = address(0x1234);
    address relayer = address(0x2222);
    address pauser = address(0x3333);
    address nonAdmin = address(0x5555);

    uint256 constant initialBalance = 1_000 ether;

    error EnforcedPause();
    error ECDSAInvalidSignatureLength(uint256 length);

    function setUp() public {
        deployer = address(3);

        vm.startPrank(deployer);
        bridge = new BridgeFactory();

        token = new MockERC20("Token", "USDC");
        token.mint(user, initialBalance);

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
        emit BridgeFactory.NativeLocked(user, 1 ether, 9999, 1);
        bridge.lockNative{value: 1 ether}(9999, 1);
    }

    function testLockNativeRevertsZeroValue() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.lockNative(9999, 1);
    }

    function testLockNativeRevertsZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.lockNative(0, 1);
    }

    function testLockNativeRevertsInvalidTargetChain() public {
        vm.chainId(1234);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.lockNative{value: 2 ether}(1234, 1);
    }

    function testFuzzLockNative(uint256 amount, uint256 targetChainId, uint256 nonceFuzz) public {
        vm.assume(amount > 0 && amount < 10 ether);
        vm.assume(targetChainId != 0 && targetChainId != block.chainid);

        vm.deal(user, amount);
        vm.prank(user);

        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.NativeLocked(user, amount, targetChainId, nonceFuzz);

        bridge.lockNative{value: amount}(targetChainId, nonceFuzz);
    }

    function testLockTokenTransfersSuccess() public {
        vm.startPrank(user);
        token.approve(address(bridge), 1 ether);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenLocked(user, address(token), 1 ether, 9999, 1);
        bridge.lockToken(address(token), 1 ether, 9999, 1);
        vm.stopPrank();

        assertEq(token.balanceOf(user), initialBalance - 1 ether);
        assertEq(token.balanceOf(address(bridge)), 1 ether);
    }

    function testLockTokenRevertsZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.lockToken(address(token), 0, 0, 1);
    }

    function testLockTokenRevertsZeroTokenAddress() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.lockToken(address(0), 1 ether, 0, 1);
    }

    function testLockTokenRevertsZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.lockToken(address(token), 1 ether, 0, 1);
    }

    function testLockTokenRevertsInvalidTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        vm.chainId(9999);
        bridge.lockToken(address(token), 1 ether, 9999, 1);
    }

    function testLockTokenRevertsIfNotApproved() public {
        vm.prank(user);
        vm.expectRevert();
        bridge.lockToken(address(token), 1 ether, 9999, 1);
    }

    function testLockTokenRevertsOnTransferFromReturningFalse() public {
        MockRevertingTransferFromToken failToken = new MockRevertingTransferFromToken();
        vm.prank(user);
        vm.expectRevert(BridgeFactory.TokenTransferFailed.selector);
        bridge.lockToken(address(failToken), 1 ether, 9999, 1);
    }

    function testFuzzLockToken(uint256 amount, uint256 targetChainId, uint256 nonceFuzz) public {
        vm.assume(amount > 0 && amount < initialBalance);
        vm.assume(targetChainId != 0 && targetChainId != block.chainid);

        vm.startPrank(user);
        token.approve(address(bridge), amount);

        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenLocked(user, address(token), amount, targetChainId, nonceFuzz);

        bridge.lockToken(address(token), amount, targetChainId, nonceFuzz);
        vm.stopPrank();

        assertEq(token.balanceOf(user), initialBalance - amount);
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    function testLockTokenWithPermitSuccess() public {
        (address user1, uint256 userPrivateKey) = makeAddrAndKey("user1");

        MockERC20 tokenWithPermit = new MockERC20("TokenPermit", "TP");
        tokenWithPermit.mint(user1, 10 ether);

        vm.startPrank(user1);

        uint256 deadline = block.timestamp + 1 hours;
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

        bridge.lockTokenWithPermit(address(tokenWithPermit), 1 ether, 9999, 1, deadline, v, r, s);

        vm.stopPrank();

        assertEq(tokenWithPermit.balanceOf(user1), 10 ether - 1 ether);
        assertEq(tokenWithPermit.balanceOf(address(bridge)), 1 ether);
    }

    function testLockTokenWithPermitRevertsZeroAddress() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.lockTokenWithPermit(address(0), 1 ether, 9999, 1, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testLockTokenWithPermitRevertsZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.lockTokenWithPermit(address(token), 0, 9999, 1, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testLockTokenWithPermitRevertsZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.lockTokenWithPermit(address(token), 1 ether, 0, 1, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testLockTokenWithPermitRevertsInvalidTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        vm.chainId(9999);
        bridge.lockTokenWithPermit(address(token), 1 ether, 9999, 1, block.timestamp + 1, 0, bytes32(0), bytes32(0));
    }

    function testClaimWrappedWithSignatureRevertsEmptySignature() public {
        vm.prank(user);
        vm.expectRevert();
        bridge.claimWrappedWithSignature(user, address(token), 1 ether, nonce, sourceChainId, "");
    }

    function testClaimWrappedWithSignatureRevertsTooShortSignature() public {
        vm.prank(user);
        vm.expectRevert();
        bridge.claimWrappedWithSignature(user, address(token), 1 ether, nonce, sourceChainId, hex"1234");
    }

    function testClaimWrappedWithSignatureRevertZeroUser() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.claimWrappedWithSignature(address(0), address(token), 1 ether, nonce, sourceChainId, hex"");
    }

    function testClaimWrappedWithSignatureRevertZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.claimWrappedWithSignature(user, address(token), 0, nonce, sourceChainId, hex"");
    }

    function testClaimWrappedWithSignatureRevertZeroSourceChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.claimWrappedWithSignature(user, address(token), 1 ether, nonce, 0, hex"");
    }

    function testClaimWrappedWithSignatureRevertSourceChainIsCurrentChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.claimWrappedWithSignature(user, address(token), 1 ether, nonce, block.chainid, hex"");
    }

    function testClaimWrappedWithSignatureRevertInvalidSignerRole() public {
        uint256 fakeRelayerKey = 0x1234;

        uint256 amount = 1 ether;
        bytes32 message = keccak256(abi.encode(user, address(token), amount, nonce, sourceChainId, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeRelayerKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidSignature.selector));
        bridge.claimWrappedWithSignature(user, address(token), amount, nonce, sourceChainId, signature);
    }

    function testClaimWrappedWithSignatureTokenRevertInvalidWrappedToken() public {
        address unregisteredToken = address(5);

        uint256 relayerPrivateKey = 0xA22CE;
        address relayerAddr = vm.addr(relayerPrivateKey);

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        bytes32 message =
            keccak256(abi.encodePacked(user, unregisteredToken, amount, nonce, sourceChainId, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.claimWrappedWithSignature(user, unregisteredToken, amount, nonce, sourceChainId, signature);
    }

    function testClaimWrappedWithSignatureRevertUnregisteredWrappedTokenNative() public {
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        address nativeToken = address(0);

        bytes32 message = keccak256(abi.encodePacked(user, nativeToken, amount, nonce, sourceChainId, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.claimWrappedWithSignature(user, nativeToken, amount, nonce, sourceChainId, signature);
    }

    function testClaimWrappedWithSignatureRevertUnregisteredWrappedToken() public {
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        address nativeToken = address(0);

        bytes32 message = keccak256(abi.encodePacked(user, nativeToken, amount, nonce, sourceChainId, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.claimWrappedWithSignature(user, nativeToken, amount, nonce, sourceChainId, signature);
    }

    function testClaimWrappedWithSignatureWhenNativeSuccess() public {
        uint256 amount = 1 ether;
        address tokenZero = address(0);
        uint256 relayerPrivateKey = 0xa0184aea8af0b8c660e4a5a58553ec5c18d670251bd4df58e14bd9308b2e5484;
        address relayer1 = vm.addr(relayerPrivateKey);

        vm.startPrank(deployer);

        WERC20 newWrappedNative = new WERC20("Wrapped Native", "wETH", 18);

        newWrappedNative.grantRole(keccak256("BRIDGE_ROLE"), address(bridge));

        bridge.registerWrappedToken(tokenZero, address(newWrappedNative));

        bridge.grantRelayerRole(relayer1);

        vm.stopPrank();

        vm.deal(address(bridge), amount);

        bytes32 message = keccak256(abi.encodePacked(user, tokenZero, amount, nonce, sourceChainId, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);

        vm.prank(user);
        bridge.claimWrappedWithSignature(user, tokenZero, amount, nonce, sourceChainId, abi.encodePacked(r, s, v));

        bool used = bridge.usedNonces(user, nonce, sourceChainId);
        assertTrue(used);
    }

    function testClaimWrappedWithSignatureFailsInvalidSignature() public {
        uint256 amount = 1 ether;
        address token1 = address(0);

        bytes memory invalidSig = hex"aaaaaaaa";

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ECDSAInvalidSignatureLength.selector, 4));
        bridge.claimWrappedWithSignature(user, token1, amount, nonce, sourceChainId, invalidSig);
    }

    function testClaimOriginalWithSignatureRevertZeroUser() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.claimOriginalWithSignature(address(0), address(token), 1 ether, nonce, sourceChainId, hex"");
    }

    function testClaimOriginalWithSignatureRevertZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.claimOriginalWithSignature(user, address(token), 0, nonce, sourceChainId, hex"");
    }

    function testClaimOriginalWithSignatureRevertZeroTargetChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.claimOriginalWithSignature(user, address(token), 1 ether, nonce, 0, hex"");
    }

    function testClaimOriginalWithSignatureRevertTargetChainIsCurrentChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.claimOriginalWithSignature(user, address(token), 1 ether, nonce, 9999, hex"");
    }

    function testClaimOriginalWithSignatureRevertNonceAlreadyUsed() public {
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;

        bytes32 message =
            keccak256(abi.encodePacked(user, address(token), amount, nonce, block.chainid, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        token.mint(address(bridge), amount);

        vm.prank(user);
        bridge.claimOriginalWithSignature(user, address(token), amount, nonce, block.chainid, signature);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ClaimAlreadyProcessed.selector));
        bridge.claimOriginalWithSignature(user, address(token), amount, nonce, block.chainid, signature);
    }

    function testClaimOriginalWithSignatureRevertInvalidSignerRole() public {
        (, uint256 fakePrivateKey) = makeAddrAndKey("faker");

        uint256 amount = 1 ether;
        bytes32 message =
            keccak256(abi.encodePacked(user, address(token), amount, nonce, block.chainid, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakePrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidSignature.selector));
        bridge.claimOriginalWithSignature(user, address(token), amount, nonce, block.chainid, signature);
    }

    function testClaimOriginalWithSignatureNativeSuccess() public {
        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        address tokenZero = address(0);

        vm.deal(address(bridge), amount);

        bytes32 message = keccak256(abi.encodePacked(user, tokenZero, amount, nonce, block.chainid, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.NativeReleased(user, amount);

        bridge.claimOriginalWithSignature(user, tokenZero, amount, nonce, block.chainid, signature);

        assertTrue(bridge.usedNonces(user, nonce, block.chainid));
    }

    function testClaimOriginalWithSignatureRevertTokenTransferFailed() public {
        MockRevertingTransferFromToken badToken = new MockRevertingTransferFromToken();

        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;

        bytes32 message =
            keccak256(abi.encodePacked(user, address(badToken), amount, nonce, block.chainid, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.TokenTransferFailed.selector));
        bridge.claimOriginalWithSignature(user, address(badToken), amount, nonce, block.chainid, signature);
    }

    function testClaimOriginalWithSignatureTokenSuccess() public {
        MockERC20 goodToken = new MockERC20("GoodToken", "GTK");
        goodToken.mint(address(bridge), 10 ether);

        (address relayerAddr, uint256 relayerPrivateKey) = makeAddrAndKey("relayer");

        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;

        bytes32 message =
            keccak256(abi.encodePacked(user, address(goodToken), amount, nonce, block.chainid, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPrivateKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit BridgeFactory.TokenReleased(user, address(goodToken), amount);

        bridge.claimOriginalWithSignature(user, address(goodToken), amount, nonce, block.chainid, signature);

        assertEq(goodToken.balanceOf(user), amount);

        bool used = bridge.usedNonces(user, nonce, block.chainid);
        assertTrue(used);
    }

    function testClaimOriginalWithSignatureEthTransferFails() public {
        RejectEthReceiver badReceiver = new RejectEthReceiver();

        (address relayerAddr, uint256 relayerKey) = makeAddrAndKey("relayer");
        vm.prank(deployer);
        bridge.grantRelayerRole(relayerAddr);

        uint256 amount = 1 ether;
        bytes32 message =
            keccak256(abi.encodePacked(badReceiver, address(0), amount, nonce, block.chainid, address(bridge)));
        bytes32 signedMessage = MessageHashUtils.toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerKey, signedMessage);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(badReceiver));
        vm.expectRevert(BridgeFactory.EthTransferFailed.selector);
        bridge.claimOriginalWithSignature(address(badReceiver), address(0), amount, nonce, block.chainid, signature);
    }

    function testBurnWrappedForReturnRevertZeroAddress() public {
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAddressNotAllowed.selector));
        bridge.burnWrappedForReturn(address(0), address(token), 1 ether, 9999, 1);
        vm.stopPrank();
    }

    function testBurnWrappedForReturnRevertZeroAmount() public {
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroAmountNotAllowed.selector));
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 0, 9999, 1);
        vm.stopPrank();
    }

    function testBurnWrappedForReturnRevertUnregisteredWrappedToken() public {
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.UnregisteredWrappedToken.selector));
        bridge.burnWrappedForReturn(address(0x9999), address(token), 1 ether, 9999, 1);
        vm.stopPrank();
    }

    function testBurnWrappedForReturnRevertZeroOriginalChainId() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.ZeroTargetChainNotAllowed.selector));
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 1 ether, 0, nonce);
    }

    function testBurnWrappedForReturnRevertOriginalChainIsCurrentChain() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeFactory.InvalidTargetChain.selector));
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 1 ether, block.chainid, nonce);
    }

    function testBurnWrappedForReturnEmitsEvent() public {
        vm.startPrank(address(bridge));

        wrappedToken.bridgeMint(user, 10 ether);

        vm.stopPrank();

        vm.startPrank(user);
        vm.expectEmit(true, true, true, true);
        emit BridgeFactory.TokenBurned(user, address(wrappedToken), address(token), 10 ether, 9999, nonce);
        bridge.burnWrappedForReturn(address(wrappedToken), address(token), 10 ether, 9999, nonce);
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
}
