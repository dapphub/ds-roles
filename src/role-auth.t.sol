pragma solidity ^0.4.4;

import 'ds-test/test.sol';
import 'ds-auth/auth.sol';
import './role-auth.sol';

contract authed is DSAuth {
	bool public flag1;
	bool public flag2;
	function cap1() auth {
		flag1 = true;
	}
	function cap2() auth {
		flag2 = true;
	}
}

contract DSRoleAuthTest is DSTest {
	DSRoleAuth r;
	authed a;
	function setUp() {
		r = new DSRoleAuth();
		a = new authed();
	}

	function testBasics() {
		uint8 root_role = 0;
		uint8 admin_role = 1;
		uint8 mod_role = 2;
		uint8 user_role = 3;

		r.setUserRole(this, root_role, true);
		r.setUserRole(this, admin_role, true);

		assertEq32(bytes32(0x3), r.getUserRoles(this));

		r.setRoleCapability(admin_role, a, bytes4(sha3("cap1()")), true);

		assert(r.canCall(this, a, bytes4(sha3("cap1()"))));
		a.cap1();
		assert(a.flag1());
	

		r.setRoleCapability(admin_role, a, bytes4(sha3("cap1()")), false);
		assert(!r.canCall(this, a, bytes4(sha3("cap1()"))));

		assert(r.hasUserRole(this, root_role));
		assert(r.hasUserRole(this, admin_role));
		assert(!r.hasUserRole(this, mod_role));
		assert(!r.hasUserRole(this, user_role));
	}

	function testRoot() {
		assert(!r.isUserRoot(this));
		assert(!r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setRootUser(this, true);
		assert(r.isUserRoot(this));
		assert(r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setRootUser(this, false);
		assert(!r.isUserRoot(this));
		assert(!r.canCall(this, a, bytes4(sha3("cap1()"))));
	}

	function testPublicCapabilities() {
		assert(!r.isCapabilityPublic(a, bytes4(sha3("cap1()"))));
		assert(!r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setPublicCapability(a, bytes4(sha3("cap1()")), true);
		assert(r.isCapabilityPublic(a, bytes4(sha3("cap1()"))));
		assert(r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setPublicCapability(a, bytes4(sha3("cap1()")), false);
		assert(!r.isCapabilityPublic(a, bytes4(sha3("cap1()"))));
		assert(!r.canCall(this, a, bytes4(sha3("cap1()"))));
	}
}
