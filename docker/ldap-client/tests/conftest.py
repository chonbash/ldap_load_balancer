"""
Pytest fixtures for LDAP Load Balancer integration tests.
Config from environment (same defaults as env.sh).
"""
import os

import ldap
import pytest


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _apply_ldap_tls(conn, uri: str) -> None:
    """Apply TLS options for LDAPS: CA cert and/or disable cert verification (tests only)."""
    if not uri.startswith("ldaps://"):
        return
    tls_reqcert = os.environ.get("LDAP_TLS_REQCERT", "").strip().lower()
    tls_cacert = os.environ.get("LDAP_TLS_CACERT", "").strip()
    if tls_reqcert == "never":
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    if tls_cacert:
        conn.set_option(ldap.OPT_X_TLS_CACERTFILE, tls_cacert)
    conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)


@pytest.fixture(scope="session")
def ldap_scheme():
    return _env("LDAP_SCHEME", "ldap")


@pytest.fixture(scope="session")
def ldap_host():
    return _env("LDAP_HOST", "ldap-load-balancer")


@pytest.fixture(scope="session")
def ldap_port():
    return _env("LDAP_PORT", "1389")


@pytest.fixture(scope="session")
def ldap_uri(ldap_scheme, ldap_host, ldap_port):
    return f"{ldap_scheme}://{ldap_host}:{ldap_port}"


@pytest.fixture(scope="session")
def base_dn():
    return _env("BASE_DN", "dc=example,dc=com")


@pytest.fixture(scope="session")
def bind_dn():
    return _env("BIND_DN", "cn=admin,dc=example,dc=com")


@pytest.fixture(scope="session")
def bind_pw():
    return _env("BIND_PW", "secret")


@pytest.fixture(scope="session")
def test_user_ou():
    return _env("TEST_USER_OU", "ou=users")


@pytest.fixture(scope="session")
def test_user_cn():
    return _env("TEST_USER_CN", "testuser")


@pytest.fixture(scope="session")
def test_user_dn(test_user_ou, base_dn, test_user_cn):
    return _env("TEST_USER_DN", f"cn={test_user_cn},{test_user_ou},{base_dn}")


@pytest.fixture(scope="session")
def test_user_pw():
    return _env("TEST_USER_PW", "testpass")


@pytest.fixture(scope="session")
def metrics_host():
    return _env("METRICS_HOST", "ldap-load-balancer")


@pytest.fixture(scope="session")
def metrics_port():
    return _env("METRICS_PORT", "9090")


@pytest.fixture(scope="session")
def metrics_url(metrics_host, metrics_port):
    return f"http://{metrics_host}:{metrics_port}"


@pytest.fixture(scope="session")
def apply_ldap_tls():
    """Fixture exposing TLS helper for tests that create their own connection (LDAPS)."""
    return _apply_ldap_tls


@pytest.fixture
def ldap_conn(ldap_uri, bind_dn, bind_pw):
    """Per-test LDAP connection (bind as admin)."""
    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    _apply_ldap_tls(conn, ldap_uri)
    conn.simple_bind_s(bind_dn, bind_pw)
    try:
        yield conn
    finally:
        conn.unbind_s()


def _ensure_test_user_on_conn(conn, ou_dn, test_user_dn, test_user_cn, test_user_pw):
    """Create OU and test user on one connection (idempotent)."""
    try:
        conn.search_s(ou_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        conn.add_s(
            ou_dn,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [b"users"]),
            ],
        )
    try:
        conn.search_s(test_user_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        conn.add_s(
            test_user_dn,
            [
                ("objectClass", [b"inetOrgPerson"]),
                ("cn", [test_user_cn.encode()]),
                ("sn", [b"Test"]),
                ("uid", [test_user_cn.encode()]),
                ("userPassword", [test_user_pw.encode()]),
            ],
        )


@pytest.fixture(scope="session")
def ensure_test_user(ldap_uri, bind_dn, bind_pw, base_dn, test_user_ou, test_user_dn, test_user_cn, test_user_pw):
    """
    Session-scoped: create OU and test user (idempotent).
    Uses ldap_uri (LB) first; if LDAP_BACKEND_URIS is set, also creates on each backend
    so that round_robin always finds the user (no replication).
    """
    ou_dn = f"{test_user_ou},{base_dn}"
    uris = [ldap_uri]
    backend_uris = _env("LDAP_BACKEND_URIS", "").strip()
    if backend_uris:
        uris = [u.strip() for u in backend_uris.split(",") if u.strip()]
    for uri in uris:
        conn = ldap.initialize(uri)
        conn.protocol_version = ldap.VERSION3
        _apply_ldap_tls(conn, uri)
        try:
            conn.simple_bind_s(bind_dn, bind_pw)
            _ensure_test_user_on_conn(conn, ou_dn, test_user_dn, test_user_cn, test_user_pw)
        finally:
            conn.unbind_s()
