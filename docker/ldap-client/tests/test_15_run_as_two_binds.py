"""Scenario 15: Run as — admin bind + search, then user bind + search."""
import ldap
import pytest


@pytest.mark.order(15)
def test_run_as_two_binds(
    ldap_uri, bind_dn, bind_pw, base_dn, test_user_dn, test_user_pw, ensure_test_user, apply_ldap_tls
):
    """Admin search base one level; then user search own entry."""
    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    apply_ldap_tls(conn, ldap_uri)
    conn.simple_bind_s(bind_dn, bind_pw)
    conn.search_s(base_dn, ldap.SCOPE_ONELEVEL, "(objectclass=*)", ["dn"])
    conn.unbind_s()

    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    apply_ldap_tls(conn, ldap_uri)
    conn.simple_bind_s(test_user_dn, test_user_pw)
    conn.search_s(test_user_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    conn.unbind_s()
