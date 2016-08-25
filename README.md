ds-roles
===

A `DSAuthority` that manages up to 256 **roles**.

In the context of the Role Authority, a **user** is the sender, while a **capability** is a `(code,sig) :: (bytes32,bytes4)` pair.

The ability to check permissions in constant time is entirely due to the artificial constraint on number of roles.

256 was chosen because this lets us abuse the large word size and cheap native bitwise operators.

