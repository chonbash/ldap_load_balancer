"""Scenario 05: Bind + compare (objectClass:organization on base)."""
import pytest


@pytest.mark.order(5)
def test_bind_compare(ldap_conn, base_dn):
    """Compare attribute objectClass=organization on base DN."""
    result = ldap_conn.compare_s(base_dn, "objectClass", "organization")
    assert result is True
