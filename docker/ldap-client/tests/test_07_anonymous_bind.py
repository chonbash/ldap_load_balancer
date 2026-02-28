"""Scenario 07: Anonymous bind and read of a dedicated test entry."""
import ldap
import pytest

ANONYMOUS_TEST_OU = "ou=anonymous-test"
ANONYMOUS_TEST_CN = "cn=public"


@pytest.mark.order(7)
def test_anonymous_bind(ldap_conn, ldap_uri, base_dn, apply_ldap_tls):
    """
    Create an OU and entry as admin, then bind anonymously and verify read access to that entry.
    Skips if anonymous bind is disabled or server does not allow anonymous read.
    """
    ou_dn = f"{ANONYMOUS_TEST_OU},{base_dn}"
    entry_dn = f"{ANONYMOUS_TEST_CN},{ou_dn}"

    # 1. Create target object (idempotent)
    try:
        ldap_conn.search_s(ou_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            ou_dn,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [b"anonymous-test"]),
            ],
        )

    try:
        ldap_conn.search_s(entry_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            entry_dn,
            [
                ("objectClass", [b"organizationalRole"]),
                ("cn", [b"public"]),
                ("description", [b"Entry for anonymous read test"]),
            ],
        )

    # 2. Anonymous bind and read
    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    apply_ldap_tls(conn, ldap_uri)

    try:
        conn.simple_bind_s()
    except ldap.INVALID_CREDENTIALS:
        conn.unbind_s()
        pytest.skip("Anonymous bind disabled on server")
    except ldap.SERVER_DOWN as e:
        conn.unbind_s()
        pytest.fail(f"Connection failed: {e}")

    try:
        result = conn.search_s(entry_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn", "description"])
        conn.unbind_s()
    except ldap.NO_SUCH_OBJECT:
        conn.unbind_s()
        pytest.skip("Anonymous bind allowed but read denied for this entry (server ACL)")
    except Exception as e:
        conn.unbind_s()
        if "anonymous" in str(e).lower() or "unwilling" in str(e).lower():
            pytest.skip("Anonymous access restricted by server")
        raise

    assert len(result) == 1, f"Expected one entry for {entry_dn}, got {result}"
    assert result[0][0] == entry_dn

    # 3. Cleanup: remove test entry and OU
    try:
        ldap_conn.delete_s(entry_dn)
    except ldap.LDAPError:
        pass
    try:
        ldap_conn.delete_s(ou_dn)
    except ldap.LDAPError:
        pass
