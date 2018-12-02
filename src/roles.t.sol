// roles.t.sol - test for roles.sol

// Copyright (C) 2017  DappHub, LLC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity >=0.4.23;

import 'ds-test/test.sol';
import 'ds-auth/auth.sol';
import './roles.sol';

contract authed is DSAuth {
	bool public flag1;
	bool public flag2;
	function cap1() public auth {
		flag1 = true;
	}
	function cap2() public auth {
		flag2 = true;
	}
}

contract DSRolesTest is DSTest {
	DSRoles r;
	address a;
    address self;
	function setUp() public {
		r = new DSRoles();
		a = address(new authed());
        self = address(this);
	}

	function testBasics() public {
		uint8 root_role = 0;
		uint8 admin_role = 1;
		uint8 mod_role = 2;
		uint8 user_role = 3;

		r.setUserRole(self, root_role, true);
		r.setUserRole(self, admin_role, true);

		assertEq32(bytes32(hex"0000000000000000000000000000000000000000000000000000000000000003"), r.getUserRoles(self));

		r.setRoleCapability(admin_role, a, bytes4(keccak256("cap1()")), true);

		assertTrue(r.canCall(self, a, bytes4(keccak256("cap1()"))));
		authed(a).cap1();
		assertTrue(authed(a).flag1());
	

		r.setRoleCapability(admin_role, a, bytes4(keccak256("cap1()")), false);
		assertTrue(!r.canCall(self, a, bytes4(keccak256("cap1()"))));

		assertTrue(r.hasUserRole(self, root_role));
		assertTrue(r.hasUserRole(self, admin_role));
		assertTrue(!r.hasUserRole(self, mod_role));
		assertTrue(!r.hasUserRole(self, user_role));
	}

	function testRoot() public {
		assertTrue(!r.isUserRoot(self));
		assertTrue(!r.canCall(self, a, bytes4(keccak256("cap1()"))));

		r.setRootUser(self, true);
		assertTrue(r.isUserRoot(self));
		assertTrue(r.canCall(self, a, bytes4(keccak256("cap1()"))));

		r.setRootUser(self, false);
		assertTrue(!r.isUserRoot(self));
		assertTrue(!r.canCall(self, a, bytes4(keccak256("cap1()"))));
	}

	function testPublicCapabilities() public {
		assertTrue(!r.isCapabilityPublic(a, bytes4(keccak256("cap1()"))));
		assertTrue(!r.canCall(self, a, bytes4(keccak256("cap1()"))));

		r.setPublicCapability(a, bytes4(keccak256("cap1()")), true);
		assertTrue(r.isCapabilityPublic(a, bytes4(keccak256("cap1()"))));
		assertTrue(r.canCall(self, a, bytes4(keccak256("cap1()"))));

		r.setPublicCapability(a, bytes4(keccak256("cap1()")), false);
		assertTrue(!r.isCapabilityPublic(a, bytes4(keccak256("cap1()"))));
		assertTrue(!r.canCall(self, a, bytes4(keccak256("cap1()"))));
	}
}
