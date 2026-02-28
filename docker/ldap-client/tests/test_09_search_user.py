"""Scenario 09: Search user (getpwnam-like by uid/cn)."""
import ldap
import pytest


@pytest.mark.order(9)
def test_search_user(ldap_conn, base_dn, test_user_cn, ensure_test_user):
    """Search user by uid or cn (getpwnam-like)."""
    ldap_conn.search_s(
        base_dn,
        ldap.SCOPE_SUBTREE,
        f"(|(uid={test_user_cn})(cn={test_user_cn}))",
        ["dn", "uid", "cn", "sn"],
    )
