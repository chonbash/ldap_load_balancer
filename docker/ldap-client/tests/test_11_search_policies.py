"""Scenario 11: Search policies (GPO-like: read base)."""
import ldap
import pytest


@pytest.mark.order(11)
def test_search_policies(ldap_conn, base_dn, ensure_test_user):
    """GPO-like: read base, objectClass, o."""
    ldap_conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn", "objectClass", "o"])
