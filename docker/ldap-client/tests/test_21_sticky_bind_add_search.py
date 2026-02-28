"""Scenario 21: Sticky session — add entry then search (same backend)."""
import ldap
import time
import pytest


@pytest.mark.order(21)
def test_sticky_add_then_search(ldap_conn, base_dn):
    """Ensure sticky-test OU exists, add entry, search it."""
    sticky_ou = "ou=sticky-test"
    sticky_ou_dn = f"{sticky_ou},{base_dn}"
    ts = int(time.time())
    sticky_cn = f"sticky-{ts}"
    sticky_dn = f"cn={sticky_cn},{sticky_ou_dn}"

    try:
        ldap_conn.search_s(sticky_ou_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            sticky_ou_dn,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [b"sticky-test"]),
            ],
        )

    ldap_conn.add_s(
        sticky_dn,
        [
            ("objectClass", [b"person"]),
            ("cn", [sticky_cn.encode()]),
            ("sn", [b"test"]),
        ],
    )
    result = ldap_conn.search_s(sticky_dn, ldap.SCOPE_BASE, "(objectClass=*)", ["cn"])
    assert result
