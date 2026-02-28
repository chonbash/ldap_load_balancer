"""Scenario 14: Password modify (set same password to verify operation)."""
import ldap
import pytest


@pytest.mark.order(14)
def test_password_modify(ldap_conn, test_user_dn, test_user_pw, ldap_uri, ensure_test_user, apply_ldap_tls):
    """Set password via modify; then bind as user to verify."""
    ldap_conn.modify_s(
        test_user_dn,
        [(ldap.MOD_REPLACE, "userPassword", [test_user_pw.encode()])],
    )
    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    apply_ldap_tls(conn, ldap_uri)
    conn.simple_bind_s(test_user_dn, test_user_pw)
    conn.unbind_s()
