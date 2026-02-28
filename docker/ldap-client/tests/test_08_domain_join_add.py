"""Scenario 08: Domain join — add OU and test user (idempotent)."""
import ldap
import pytest


@pytest.mark.order(8)
def test_domain_join_add_ou_and_user(
    ldap_conn, base_dn, test_user_ou, test_user_dn, test_user_cn, test_user_pw
):
    """Create OU and test user (idempotent); used by 09–17."""
    ou_dn = f"{test_user_ou},{base_dn}"
    # Ensure OU exists
    try:
        ldap_conn.search_s(ou_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            ou_dn,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [b"users"]),
            ],
        )
    # Ensure test user exists
    try:
        ldap_conn.search_s(test_user_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            test_user_dn,
            [
                ("objectClass", [b"inetOrgPerson"]),
                ("cn", [test_user_cn.encode()]),
                ("sn", [b"Test"]),
                ("uid", [test_user_cn.encode()]),
                ("userPassword", [test_user_pw.encode()]),
            ],
        )
