"""Scenario 23: Create user, group, add user to group (idempotent)."""
import ldap
import os
import pytest


@pytest.fixture
def script_user_group(ldap_conn, base_dn):
    """Create ou=groups, demouser, demogroup with user as member (idempotent)."""
    group_ou = os.environ.get("SCRIPT_GROUP_OU", "ou=groups")
    user_ou = os.environ.get("SCRIPT_USER_OU", "ou=users")
    user_cn = os.environ.get("SCRIPT_USER_CN", "demouser")
    user_pw = os.environ.get("SCRIPT_USER_PW", "demopass")
    group_cn = os.environ.get("SCRIPT_GROUP_CN", "demogroup")
    groups_ou_dn = f"{group_ou},{base_dn}"
    user_dn = f"cn={user_cn},{user_ou},{base_dn}"
    group_dn = f"cn={group_cn},{group_ou},{base_dn}"

    try:
        ldap_conn.search_s(groups_ou_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            groups_ou_dn,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [b"groups"]),
            ],
        )

    try:
        ldap_conn.search_s(user_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            user_dn,
            [
                ("objectClass", [b"inetOrgPerson"]),
                ("cn", [user_cn.encode()]),
                ("sn", [b"Demo"]),
                ("uid", [user_cn.encode()]),
                ("userPassword", [user_pw.encode()]),
            ],
        )

    try:
        ldap_conn.search_s(group_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            group_dn,
            [
                ("objectClass", [b"groupOfNames"]),
                ("cn", [group_cn.encode()]),
                ("member", [user_dn.encode()]),
            ],
        )
    else:
        # Group exists — add user to member if not already
        res = ldap_conn.search_s(
            group_dn, ldap.SCOPE_BASE, f"(member={user_dn})", ["dn"]
        )
        if not res:
            ldap_conn.modify_s(
                group_dn,
                [(ldap.MOD_ADD, "member", [user_dn.encode()])],
            )


@pytest.mark.order(23)
def test_create_user_group(ldap_conn, base_dn, script_user_group):
    """Create user, group, add user to group (idempotent)."""
    group_ou = os.environ.get("SCRIPT_GROUP_OU", "ou=groups")
    group_cn = os.environ.get("SCRIPT_GROUP_CN", "demogroup")
    group_dn = f"cn={group_cn},{group_ou},{base_dn}"
    ldap_conn.search_s(group_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn", "member"])
    # If we get here without exception, fixture already created/updated
    pass
