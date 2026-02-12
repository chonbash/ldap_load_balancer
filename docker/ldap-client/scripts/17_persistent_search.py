#!/usr/bin/env python3
"""
Persistent search (RFC 4533 refreshAndPersist) test helper.
Runs syncrepl in background: prints READY when refresh phase is done,
then ENTRY:<dn> for each change. Exits 0 when 2 change entries received, 1 on timeout/error.
"""
import os
import sys
import time

import ldap
from ldap.syncrepl import SyncreplConsumer

# From env (set by 17_persistent_search.sh)
LDAP_URI = os.environ["LDAP_URI"]
BIND_DN = os.environ["BIND_DN"]
BIND_PW = os.environ["BIND_PW"]
BASE_DN = os.environ["BASE_DN"]
TEST_USER_OU = os.environ.get("TEST_USER_OU", "ou=users")
# Search base: OU containing the test user (so we only get that entry + changes)
SEARCH_BASE = f"{TEST_USER_OU},{BASE_DN}"

# Need 2 change entries (after refresh) to pass
REQUIRED_PERSIST_ENTRIES = 2
TIMEOUT_SEC = 25
POLL_TIMEOUT = 1


class Consumer(SyncreplConsumer):
    """Delegates search_ext/result4 to the LDAP connection."""

    def __init__(self, conn):
        self._conn = conn
        self._cookie = None
        self._refresh_done = False
        self._persist_count = 0

    def search_ext(self, base, scope, *args, **kwargs):
        return self._conn.search_ext(base, scope, *args, **kwargs)

    def result4(self, *args, **kwargs):
        return self._conn.result4(*args, **kwargs)

    def syncrepl_get_cookie(self):
        return self._cookie

    def syncrepl_set_cookie(self, cookie):
        self._cookie = cookie

    def syncrepl_present(self, uuids, refreshDeletes=False):
        pass

    def syncrepl_delete(self, uuids):
        pass

    def syncrepl_entry(self, dn, attrs, uuid):
        if self._refresh_done:
            self._persist_count += 1
            print(f"ENTRY:{dn}", flush=True)
            if self._persist_count >= REQUIRED_PERSIST_ENTRIES:
                print("DONE", flush=True)
                sys.exit(0)

    def syncrepl_refreshdone(self):
        self._refresh_done = True
        print("READY", flush=True)


def main():
    conn = ldap.initialize(LDAP_URI)
    conn.protocol_version = ldap.VERSION3
    conn.simple_bind_s(BIND_DN, BIND_PW)

    consumer = Consumer(conn)
    msgid = consumer.syncrepl_search(
        SEARCH_BASE,
        ldap.SCOPE_SUBTREE,
        mode="refreshAndPersist",
        filterstr="(objectClass=inetOrgPerson)",
        attrlist=["dn", "description"],
    )

    deadline = time.monotonic() + TIMEOUT_SEC
    while time.monotonic() < deadline:
        try:
            in_progress = consumer.syncrepl_poll(msgid=msgid, timeout=POLL_TIMEOUT)
            if not in_progress:
                break
        except ldap.TIMEOUT:
            continue
        except Exception as e:
            print(f"ERROR:{e}", file=sys.stderr, flush=True)
            sys.exit(1)

    if consumer._persist_count >= REQUIRED_PERSIST_ENTRIES:
        sys.exit(0)
    print("TIMEOUT", file=sys.stderr, flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
