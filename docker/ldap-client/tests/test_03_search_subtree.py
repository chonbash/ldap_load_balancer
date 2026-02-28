"""Scenario 03: Search subtree (all objects in tree)."""
import ldap
import pytest


@pytest.mark.order(3)
def test_search_subtree(ldap_conn, base_dn):
    """Search subtree: all objects under base."""
    ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, "(objectclass=*)", ["dn"])
