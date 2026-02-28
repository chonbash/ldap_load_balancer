"""Scenario 10: Search groups (groupOfNames / groupOfUniqueNames)."""
import ldap
import pytest


@pytest.mark.order(10)
def test_search_groups(ldap_conn, base_dn, ensure_test_user):
    """Search groups by objectClass."""
    ldap_conn.search_s(
        base_dn,
        ldap.SCOPE_SUBTREE,
        "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
        ["dn", "cn"],
    )
