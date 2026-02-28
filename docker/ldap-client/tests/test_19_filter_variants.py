"""Scenario 19: Filter variants (base, AND, OR, subtree)."""
import ldap
import pytest


@pytest.mark.order(19)
def test_filter_objectclass_base(ldap_conn, base_dn):
    """Filter (objectClass=*) base scope."""
    ldap_conn.search_s(base_dn, ldap.SCOPE_BASE, "(objectClass=*)", ["cn"])


@pytest.mark.order(19)
def test_filter_and_objectclass_cn(ldap_conn, base_dn):
    """Filter (&(objectClass=*)(cn=admin))."""
    ldap_conn.search_s(
        base_dn,
        ldap.SCOPE_SUBTREE,
        "(&(objectClass=*)(cn=admin))",
        ["cn"],
    )


@pytest.mark.order(19)
def test_filter_or_cn_one_level(ldap_conn, base_dn):
    """Filter (|(cn=admin)(cn=*)) one level."""
    ldap_conn.search_s(
        base_dn,
        ldap.SCOPE_ONELEVEL,
        "(|(cn=admin)(cn=*))",
        ["cn"],
    )


@pytest.mark.order(19)
def test_filter_subtree_cn_star(ldap_conn, base_dn):
    """Filter (cn=*) subtree."""
    ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, "(cn=*)", ["cn"])
