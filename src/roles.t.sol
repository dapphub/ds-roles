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

pragma solidity ^0.4.8;

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
