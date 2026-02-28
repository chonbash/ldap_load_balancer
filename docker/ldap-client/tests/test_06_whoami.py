"""Scenario 06: WhoAmI extended operation."""
import pytest


@pytest.mark.order(6)
def test_whoami(ldap_conn):
    """WhoAmI extended op returns identity."""
    result = ldap_conn.whoami_s()
    assert result is not None
