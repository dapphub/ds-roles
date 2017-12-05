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

pragma solidity ^0.4.13;

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
	authed a;
	function setUp() public {
		r = new DSRoles();
		a = new authed();
	}

	function testBasics() public {
		uint8 root_role = 0;
		uint8 admin_role = 1;
		uint8 mod_role = 2;
		uint8 user_role = 3;

		r.acts(this, root_role, true);
		r.acts(this, admin_role, true);

		assertEq32(bytes32(0x3), r.acts(this));

		r.does(admin_role, a, bytes4(keccak256("cap1()")), true);

		assertTrue(r.canCall(this, a, bytes4(keccak256("cap1()"))));
		a.cap1();
		assertTrue(a.flag1());
	

		r.does(admin_role, a, bytes4(keccak256("cap1()")), false);
		assertTrue(!r.canCall(this, a, bytes4(keccak256("cap1()"))));

		assertTrue(r.acts(this, root_role));
		assertTrue(r.acts(this, admin_role));
		assertTrue(!r.acts(this, mod_role));
		assertTrue(!r.acts(this, user_role));
	}

	function testRoot() public {
		assertTrue(!r.root(this));
		assertTrue(!r.canCall(this, a, bytes4(keccak256("cap1()"))));

		r.setRootUser(this, true);
		assertTrue(r.root(this));
		assertTrue(r.canCall(this, a, bytes4(keccak256("cap1()"))));

		r.setRootUser(this, false);
		assertTrue(!r.root(this));
		assertTrue(!r.canCall(this, a, bytes4(keccak256("cap1()"))));
	}

	function testPublicCapabilities() public {
		assertTrue(!r.open(a, bytes4(keccak256("cap1()"))));
		assertTrue(!r.canCall(this, a, bytes4(keccak256("cap1()"))));

		r.open(a, bytes4(keccak256("cap1()")), true);
		assertTrue(r.open(a, bytes4(keccak256("cap1()"))));
		assertTrue(r.canCall(this, a, bytes4(keccak256("cap1()"))));

		r.open(a, bytes4(keccak256("cap1()")), false);
		assertTrue(!r.open(a, bytes4(keccak256("cap1()"))));
		assertTrue(!r.canCall(this, a, bytes4(keccak256("cap1()"))));
	}
}
