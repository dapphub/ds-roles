// Copyright 2016-2017  Nexus Development, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// A copy of the License may be obtained at the following URL:
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pragma solidity ^0.4.13;

import 'ds-test/test.sol';
import 'ds-auth/auth.sol';
import './roles.sol';

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

contract DSRolesTest is DSTest {
	DSRoles r;
	authed a;
	function setUp() {
		r = new DSRoles();
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

		assertTrue(r.canCall(this, a, bytes4(sha3("cap1()"))));
		a.cap1();
		assertTrue(a.flag1());
	

		r.setRoleCapability(admin_role, a, bytes4(sha3("cap1()")), false);
		assertTrue(!r.canCall(this, a, bytes4(sha3("cap1()"))));

		assertTrue(r.hasUserRole(this, root_role));
		assertTrue(r.hasUserRole(this, admin_role));
		assertTrue(!r.hasUserRole(this, mod_role));
		assertTrue(!r.hasUserRole(this, user_role));
	}

	function testRoot() {
		assertTrue(!r.isUserRoot(this));
		assertTrue(!r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setRootUser(this, true);
		assertTrue(r.isUserRoot(this));
		assertTrue(r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setRootUser(this, false);
		assertTrue(!r.isUserRoot(this));
		assertTrue(!r.canCall(this, a, bytes4(sha3("cap1()"))));
	}

	function testPublicCapabilities() {
		assertTrue(!r.isCapabilityPublic(a, bytes4(sha3("cap1()"))));
		assertTrue(!r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setPublicCapability(a, bytes4(sha3("cap1()")), true);
		assertTrue(r.isCapabilityPublic(a, bytes4(sha3("cap1()"))));
		assertTrue(r.canCall(this, a, bytes4(sha3("cap1()"))));

		r.setPublicCapability(a, bytes4(sha3("cap1()")), false);
		assertTrue(!r.isCapabilityPublic(a, bytes4(sha3("cap1()"))));
		assertTrue(!r.canCall(this, a, bytes4(sha3("cap1()"))));
	}
}
