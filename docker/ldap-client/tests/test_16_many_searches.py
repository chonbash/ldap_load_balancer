"""Scenario 16: Many sequential searches (login burst)."""
import ldap
import pytest


@pytest.mark.order(16)
def test_many_searches(ldap_conn, base_dn, ensure_test_user):
    """Ten pairs of base + onelevel search (burst)."""
    for _ in range(10):
        ldap_conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
        ldap_conn.search_s(base_dn, ldap.SCOPE_ONELEVEL, "(objectclass=*)", ["dn"])
