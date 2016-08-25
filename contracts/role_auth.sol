import 'ds-auth/auth.sol';

contract DSRoleAuth is DSAuthority
                     , DSAuth
{
    mapping(address=>bytes32) _user_roles;
    mapping(address=>bytes4=>bytes32) _capability_roles;

    function getUserRoles(address who)
        constant
        returns (bytes32)
    {
        return _user_roles[who];
    }
    function getCapabilityRoles(address code, bytes4 sig) {
    }

    function canCall(address caller, address code, bytes4 sig)
        constant
        returns (bool)
    {
        return 0 != _user_roles[caller] & _capability_roles[code][sig];
    }
    function setRole(address who, uint8 role, bool enabled)
        auth
    {
        var last_roles = _user_roles[who];
        var shifted = 1 << role;
        if( enabled ) {
            _user_roles[who] = last_roles | shifted;
        } else {
            _user_roles[who] = last_roles & !shifted;
        }
    }
    function setRoleCapability(uint8 role, address code, bytes4 sig, bool enabled)
        auth
    {
        var last_roles = _capability_roles[code][sig];
        var shifted = 1 << role;
        if( enabled ) {
            _capability_roles[code][sig]; = last_roles | shifted;
        } else {
            _capability_roles[code][sig]; = last_roles & !shifted;
        }

    }
}
