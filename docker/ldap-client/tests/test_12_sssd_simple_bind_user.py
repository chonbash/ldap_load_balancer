"""Scenario 12: SSSD simple bind as user + search own entry."""
import ldap
import pytest


@pytest.mark.order(12)
def test_sssd_simple_bind_user(ldap_uri, test_user_dn, test_user_pw, ensure_test_user, apply_ldap_tls):
    """Bind as test user, then search own entry (read self)."""
    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    apply_ldap_tls(conn, ldap_uri)
    conn.simple_bind_s(test_user_dn, test_user_pw)
    try:
        conn.whoami_s()
        conn.search_s(test_user_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    finally:
        conn.unbind_s()
