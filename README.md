<h2>DSRoles
  <small class="text-muted">
    <a href="https://github.com/dapphub/ds-roles"><span class="fa fa-github"></span></a>
  </small>
</h2>

_A DSAuthority for up to 256 roles_

A role-driven `authority` for [ds-auth](https://dapp.tools/dappsys/ds-auth) 
which facilitates access to lists of user roles and capabilities. Works as a 
set of lookup tables for the `canCall` function to provide boolean answers
as to whether a user is authorized to call a given function at given address.

The ability to check permissions in constant time is entirely due to the
artificial constraint on the number of roles. 256 was chosen because this lets
us abuse the large word size and cheap bitwise operations.

In the context of providing `authority` for DSAuth, a `user` is the `msg.sender`.
DSRoles provides 3 different ways of permitting/forbidding function call access 
to users, with root access being the most permissive:

1. **Root Users** - any users added to the `_root_users`
   whitelist will be authorized to call any function regardless of what roles or
   capabilities might be defined.

2. **Public Capabilities** - public capabilities are global
   capabilities which apply to all users and take precedence over any user
   specific role-capabilities which might be defined.
    
3. **Role Capabilities** - capabilities which are associated
   with a particular role. Role capabilities are only checked if the user
   does not have root access and the capability is not public.

**Roles** are assigned to users by number:

```solidity
uint8 owner_role = 0;
uint8 user_role = 1;

setUserRole(owner_address, owner_role, true);
setUserRole(user_address, user_role, true);
```

**Capabilities** can be assigned to anyone (public) or to a
`role` permitting/forbidding access to a particular function
at a given address:

```solidity
address target = 0x123;  // code address

bytes4 withdraw_sig = bytes4(sha3("withdrawAll()"));
setRoleCapability(owner_role, target, withdraw_sig, true);
setRoleCapability(user_role, target, withdraw_sig, false);

bytes4 deposit_sig = bytes4(sha3("deposit(uint256)"));
setRoleCapability(user_role, target, deposit_sig, true);
```

### Actions

#### `setRootUser`
grant root access to a given user (requires auth)

#### `setUserRole`
assign a role to given user (requires auth)

#### `setPublicCapability`
set public permissions for a given capability (requires auth)

#### `setRoleCapability`
set a capability for a given role (requires auth)

