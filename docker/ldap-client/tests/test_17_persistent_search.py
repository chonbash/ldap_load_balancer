"""Scenario 17: Persistent Search (RFC 4533); run helper script, apply 2 modifies."""
import os
import subprocess
import sys
import time
from pathlib import Path

import ldap
import pytest


@pytest.mark.order(17)
def test_persistent_search(
    ldap_uri,
    bind_dn,
    bind_pw,
    base_dn,
    test_user_dn,
    test_user_ou,
    ensure_test_user,
    apply_ldap_tls,
):
    """Run persistent search in background, apply 2 modifies, expect both in stream."""
    script_dir = Path(__file__).resolve().parent.parent / "scripts"
    py_script = script_dir / "17_persistent_search.py"
    if not py_script.exists():
        pytest.skip("17_persistent_search.py not found (run from container)")

    env = os.environ.copy()
    env["LDAP_URI"] = ldap_uri
    env["BIND_DN"] = bind_dn
    env["BIND_PW"] = bind_pw
    env["BASE_DN"] = base_dn
    env["TEST_USER_OU"] = test_user_ou

    proc = subprocess.Popen(
        [sys.executable, str(py_script)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out_lines = []

    def read_stdout():
        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                out_lines.append(line)

    import threading
    t = threading.Thread(target=read_stdout)
    t.daemon = True
    t.start()

    # Wait for READY (max 8 s)
    for _ in range(8):
        if proc.poll() is not None:
            t.join(timeout=1)
            _, err = proc.communicate()
            pytest.fail(f"persistent search exited before READY: {err}")
        if any("READY" in line for line in out_lines):
            break
        time.sleep(1)
    else:
        proc.kill()
        proc.wait()
        pytest.fail("no READY (sync may be unsupported by backend?)")

    # Apply two modifies
    conn = ldap.initialize(ldap_uri)
    conn.protocol_version = ldap.VERSION3
    apply_ldap_tls(conn, ldap_uri)
    conn.simple_bind_s(bind_dn, bind_pw)
    try:
        conn.modify_s(
            test_user_dn,
            [(ldap.MOD_REPLACE, "description", [b"persist-test-1"])],
        )
        time.sleep(0.5)
        conn.modify_s(
            test_user_dn,
            [(ldap.MOD_REPLACE, "description", [b"persist-test-2"])],
        )
    finally:
        conn.unbind_s()

    # Wait for process to exit (max 15 s)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail("persistent search did not receive 2 changes (timeout)")

    t.join(timeout=1)
    out = "".join(out_lines)
    if proc.returncode != 0:
        err = proc.stderr.read() if proc.stderr else ""
        pytest.fail(f"exit_code={proc.returncode} stderr={err}")
    assert "DONE" in out, "DONE not seen in output"
