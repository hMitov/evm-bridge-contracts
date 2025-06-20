// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/WERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract WERC20Test is Test {
    WERC20 token;

    address deployer = address(0x7777);
    address user = address(0x1234);
    address other = address(0x5678);

    error EnforcedPause();

    function setUp() public {
        vm.prank(deployer);
        token = new WERC20("Wrapped Token", "wTK", 6);
    }

    function testConstructorRevertsOnEmptyName() public {
        vm.expectRevert(WERC20.EmptyStringNotAllowed.selector);
        new WERC20("", "SYM", 6);
    }

    function testConstructorRevertsOnEmptySymbol() public {
        vm.expectRevert(WERC20.EmptyStringNotAllowed.selector);
        new WERC20("Name", "", 6);
    }

    function testConstructorRevertsOnZeroDecimalValue() public {
        vm.expectRevert(WERC20.ZeroAmountNotAllowed.selector);
        new WERC20("Name", "SYM", 0);
    }

    function testGrantPauserRoleSuccess() public {
        vm.prank(deployer);
        token.grantPauserRole(user);
        assertTrue(token.hasRole(token.PAUSER_ROLE(), user));
    }

    function testGrantPauserRoleRevertsOnZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(WERC20.ZeroAddressNotAllowed.selector);
        token.grantPauserRole(address(0));
    }

    function testGrantPauserRoleRevertsIfNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotAdmin.selector);
        token.grantPauserRole(other);
    }

    function testRevokePauserRoleSuccess() public {
        vm.prank(deployer);
        token.grantPauserRole(user);

        vm.prank(deployer);
        token.revokePauserRole(user);

        assertFalse(token.hasRole(token.PAUSER_ROLE(), user));
    }

    function testRevokePauserRoleRevertsOnZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(WERC20.ZeroAddressNotAllowed.selector);
        token.revokePauserRole(address(0));
    }

    function testRevokePauserRoleRevertsIfNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotAdmin.selector);
        token.revokePauserRole(user);
    }

    function testGrantBridgeRoleSuccess() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);
        assertTrue(token.hasRole(token.BRIDGE_ROLE(), user));
    }

    function testGrantBridgeRoleRevertsOnZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(WERC20.ZeroAddressNotAllowed.selector);
        token.grantBridgeRole(address(0));
    }

    function testGrantBridgeRoleRevertsIfNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotAdmin.selector);
        token.grantBridgeRole(user);
    }

    function testRevokeBridgeRoleSuccess() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(deployer);
        token.revokeBridgeRole(user);

        assertFalse(token.hasRole(token.BRIDGE_ROLE(), user));
    }

    function testRevokeBridgeRoleRevertsOnZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(WERC20.ZeroAddressNotAllowed.selector);
        token.revokeBridgeRole(address(0));
    }

    function testRevokeBridgeRoleRevertsIfNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotAdmin.selector);
        token.revokeBridgeRole(user);
    }

    function testPauseUnpauseSuccess() public {
        vm.prank(deployer);
        token.grantPauserRole(user);

        vm.prank(user);
        token.pause();
        assertTrue(token.paused());

        vm.prank(user);
        token.unpause();
        assertFalse(token.paused());
    }

    function testPauseRevertsIfNotPauser() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotPauser.selector);
        token.pause();
    }

    function testUnpauseRevertsIfNotPauser() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotPauser.selector);
        token.unpause();
    }

    function testDecimalsSuccess() public view {
        uint8 expectedDecimals = 6;

        uint8 tokenDecimals = token.decimals();

        assertEq(tokenDecimals, expectedDecimals);
    }

    function testBridgeMintSuccess() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        token.bridgeMint(user, 100 ether);

        assertEq(token.balanceOf(user), 100 ether);
    }

    function testBridgeMintRevertsIfPaused() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(deployer);
        token.pause();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(EnforcedPause.selector));
        token.bridgeMint(user, 1 ether);
    }

    function testBridgeMintRevertsIfCallerNotBridger() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotBridger.selector);
        token.bridgeMint(user, 1 ether);
    }

    function testBridgeMintRevertsOnZeroAmount() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        vm.expectRevert();
        token.bridgeMint(user, 0);
    }

    function testBridgeBurnSuccess() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        token.bridgeMint(user, 100 ether);

        vm.prank(user);
        token.bridgeBurn(user, 40 ether);

        assertEq(token.balanceOf(user), 60 ether);
    }

    function testBridgeBurnRevertsIfPaused() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        token.bridgeMint(user, 100 ether);

        vm.prank(deployer);
        token.pause();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(EnforcedPause.selector));
        token.bridgeBurn(user, 1 ether);
    }

    function testBridgeBurnRevertsIfCallerNotBridger() public {
        vm.prank(user);
        vm.expectRevert(WERC20.CallerIsNotBridger.selector);
        token.bridgeBurn(user, 1 ether);
    }

    function testBridgeBurnRevertsIfBurningMoreThanBalance() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        token.bridgeMint(user, 10 ether);

        vm.prank(user);
        vm.expectRevert();
        token.bridgeBurn(user, 20 ether);
    }

    function testBridgeBurnRevertsOnZeroAmount() public {
        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        vm.expectRevert(WERC20.ZeroAmountNotAllowed.selector);
        token.bridgeBurn(user, 0);
    }

    function testReceiveRevertsOnDirectETH() public {
        vm.expectRevert(WERC20.DirectEthTransfersNotSupported.selector);
        payable(address(token)).transfer(1 ether);
    }

    function testFallbackRevertsOnDirectETH() public {
        vm.expectRevert(WERC20.DirectEthTransfersNotSupported.selector);
        (bool success,) = address(token).call{value: 1 ether}(hex"aaaaaaaa");
        assertTrue(success);
    }

    function testPermitSuccess() public {
        (address userAddress, uint256 userPrivateKey) = makeAddrAndKey("user");
        vm.prank(deployer);
        token.grantBridgeRole(userAddress);

        address spender = address(this);
        uint256 value = 1000 * 1e6;
        uint256 nonce = token.nonces(userAddress);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 DOMAIN_SEPARATOR = token.DOMAIN_SEPARATOR();

        bytes32 PERMIT_TYPEHASH =
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, userAddress, spender, value, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);

        vm.prank(spender);
        token.permit(userAddress, spender, value, deadline, v, r, s);

        assertEq(token.allowance(userAddress, spender), value);
    }

    function testPermitRevertsWhenExpiredSignature() public {
        (address userAddress, uint256 userPrivateKey) = makeAddrAndKey("user");

        vm.prank(deployer);
        token.grantBridgeRole(userAddress);

        address spender = address(this);
        uint256 value = 1000 * 1e6;
        uint256 nonce = token.nonces(userAddress);

        uint256 deadline = block.timestamp + 1 hours;

        bytes32 DOMAIN_SEPARATOR = token.DOMAIN_SEPARATOR();

        bytes32 PERMIT_TYPEHASH =
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, userAddress, spender, value, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);

        vm.warp(deadline + 1);

        vm.prank(spender);
        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, deadline));
        token.permit(userAddress, spender, value, deadline, v, r, s);
    }

    function testPermitRevertsWithInvalidSignature() public {
        (address userAddress, uint256 userPrivateKey) = makeAddrAndKey("user");
        vm.prank(deployer);
        token.grantBridgeRole(userAddress);

        address spender = address(this);
        uint256 value = 1000 * 1e6;
        uint256 nonce = token.nonces(userAddress);
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                token.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        userAddress,
                        spender,
                        value,
                        nonce,
                        deadline
                    )
                )
            )
        );

        uint256 fakePrivateKey = userPrivateKey + 1;

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakePrivateKey, digest);

        vm.prank(spender);
        vm.expectRevert(
            abi.encodeWithSelector(ERC20Permit.ERC2612InvalidSigner.selector, vm.addr(fakePrivateKey), userAddress)
        );
        token.permit(userAddress, spender, value, deadline, v, r, s);
    }

    function testFuzzBridgeMint(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(amount > 0 && amount < 1e24);

        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        token.bridgeMint(to, amount);

        assertEq(token.balanceOf(to), amount);
    }

    function testFuzzBridgeBurn(address from, uint256 mintAmount, uint256 burnAmount) public {
        vm.assume(from != address(0));
        vm.assume(mintAmount > 0 && mintAmount < 1e24);
        vm.assume(burnAmount > 0 && burnAmount <= mintAmount);

        vm.prank(deployer);
        token.grantBridgeRole(user);

        vm.prank(user);
        token.bridgeMint(from, mintAmount);

        vm.prank(user);
        token.bridgeBurn(from, burnAmount);

        assertEq(token.balanceOf(from), mintAmount - burnAmount);
    }

    function testFuzzGrantPauserRole(address newPauser) public {
        vm.assume(newPauser != address(0));

        vm.prank(deployer);
        token.grantPauserRole(newPauser);

        assertTrue(token.hasRole(token.PAUSER_ROLE(), newPauser));
    }

    function testFuzzPauseUnpause() public {
        vm.prank(deployer);
        token.grantPauserRole(user);

        vm.prank(user);
        token.pause();
        assertTrue(token.paused());

        vm.prank(user);
        token.unpause();
        assertFalse(token.paused());
    }
}
