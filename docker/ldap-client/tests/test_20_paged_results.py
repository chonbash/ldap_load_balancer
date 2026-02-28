"""Scenario 20: Paged results control (ldapsearch -E pr=2)."""
import subprocess
import ldap
import pytest

# Page size in test; we create this many entries so we get 4 pages
PAGE_SIZE = 2
PAGED_ENTRIES_COUNT = 8  # 8 entries / 2 per page = 4 pages
PAGED_OU = "ou=paged_test"


@pytest.fixture
def paged_test_data(ldap_conn, base_dn):
    """Create ou=paged_test and 8 inetOrgPerson entries for 4-page paged search."""
    ou_dn = f"{PAGED_OU},{base_dn}"
    try:
        ldap_conn.search_s(ou_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
    except ldap.NO_SUCH_OBJECT:
        ldap_conn.add_s(
            ou_dn,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [b"paged_test"]),
            ],
        )
    for i in range(1, PAGED_ENTRIES_COUNT + 1):
        cn_val = f"user{i}"
        user_dn = f"cn={cn_val},{ou_dn}"
        try:
            ldap_conn.search_s(user_dn, ldap.SCOPE_BASE, "(objectclass=*)", ["dn"])
        except ldap.NO_SUCH_OBJECT:
            ldap_conn.add_s(
                user_dn,
                [
                    ("objectClass", [b"inetOrgPerson"]),
                    ("cn", [cn_val.encode()]),
                    ("sn", [b"Paged"]),
                    ("uid", [cn_val.encode()]),
                ],
            )
    yield
    # Optional: leave data for other runs (idempotent fixture)


@pytest.mark.order(20)
def test_paged_results(ldap_uri, bind_dn, bind_pw, base_dn, paged_test_data):
    """Search with paged results, page size 2; search base has 8 entries → 4 pages."""
    search_base = f"{PAGED_OU},{base_dn}"
    result = subprocess.run(
        [
            "ldapsearch",
            "-x",
            "-H", ldap_uri,
            "-b", search_base,
            "-D", bind_dn,
            "-w", bind_pw,
            "-LLL",
            "-E", f"pr={PAGE_SIZE}",
            "(objectClass=inetOrgPerson)",
            "cn",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    # With 8 entries and page size 2 we get 4 pages; output should contain 8 cn: lines
    cn_lines = [line for line in result.stdout.splitlines() if line.strip().startswith("cn:")]
    assert len(cn_lines) == PAGED_ENTRIES_COUNT, (
        f"Expected {PAGED_ENTRIES_COUNT} entries (4 pages), got {len(cn_lines)}"
    )
