"""Scenario 13: Modify attribute (description)."""
import time

import ldap
import pytest


@pytest.mark.order(13)
def test_modify_attribute(ldap_conn, test_user_dn, ensure_test_user):
    """Modify description on test user."""
    value = f"Updated by scenario 13 at {int(time.time())}"
    ldap_conn.modify_s(test_user_dn, [(ldap.MOD_REPLACE, "description", [value.encode()])])
