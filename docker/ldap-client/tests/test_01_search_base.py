"""Scenario 01: Search base (object by DN)."""
import ldap
import pytest


@pytest.mark.order(1)
def test_search_base(ldap_conn, base_dn):
    """Search base scope: object at base DN."""
    result = ldap_conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    assert result
