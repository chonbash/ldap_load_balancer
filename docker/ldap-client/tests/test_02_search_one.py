"""Scenario 02: Search one level (direct children)."""
import ldap
import pytest


@pytest.mark.order(2)
def test_search_one_level(ldap_conn, base_dn):
    """Search one level: direct children of base."""
    ldap_conn.search_s(base_dn, ldap.SCOPE_ONELEVEL, "(objectclass=*)", ["dn"])
