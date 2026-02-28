"""Scenario 04: Search with filter (objectClass=organization)."""
import ldap
import pytest


@pytest.mark.order(4)
def test_search_filter_objectclass(ldap_conn, base_dn):
    """Search with filter objectClass=organization, request dn and o."""
    ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, "(objectClass=organization)", ["dn", "o"])
