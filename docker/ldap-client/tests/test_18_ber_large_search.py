"""Scenario 18: BER — search with long attribute list and complex filter."""
import ldap
import pytest


@pytest.mark.order(18)
def test_ber_long_attribute_list(ldap_conn, base_dn):
    """Search with many attributes (long BER)."""
    attrs = [
        "cn",
        "mail",
        "sn",
        "givenName",
        "objectClass",
        "uid",
        "userPassword",
        "displayName",
        "description",
        "memberOf",
    ]
    ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, "(objectClass=*)", attrs)


@pytest.mark.order(18)
def test_ber_complex_filter(ldap_conn, base_dn):
    """Search with nested AND/OR filter."""
    ldap_conn.search_s(
        base_dn,
        ldap.SCOPE_SUBTREE,
        "(&(objectClass=*)(|(cn=admin)(cn=*)))",
        ["cn"],
    )
