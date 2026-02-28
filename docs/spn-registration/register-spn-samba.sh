#!/usr/bin/env bash
#
# Registers SPN(s) for LDAP load balancer on a Samba AD account (e.g. Samba DC
# computer account) so that GSSAPI/Kerberos authentication works when clients
# connect via the balancer. Uses samba-tool (and optionally ldapmodify).
#
# Usage: register-spn-samba.sh <balancer-hostname-or-fqdn> [account]
#   balancer-hostname-or-fqdn  Hostname or FQDN clients use to connect to the balancer
#   account                    Optional: sAMAccountName (e.g. DC01$). Default: local hostname$
#
# Example:
#   ./register-spn-samba.sh ldap-balancer.example.com
#   ./register-spn-samba.sh ldap-balancer DC01$
#

set -e

BALANCER_HOST="${1:?Usage: $0 <balancer-hostname-or-fqdn> [account]}"
ACCOUNT="${2:-}"

if ! command -v samba-tool &>/dev/null; then
    echo "Error: samba-tool not found. Run this script on a Samba DC or a host with Samba AD tools." >&2
    exit 1
fi

# Default account: local computer (Samba DC) — sAMAccountName is hostname$
if [[ -z "$ACCOUNT" ]]; then
    HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
    ACCOUNT="${HOSTNAME_SHORT}\$"
fi

# Ensure computer account has $ suffix if it looks like a single name
if [[ "$ACCOUNT" =~ ^[A-Za-z0-9_-]+$ ]]; then
    ACCOUNT="${ACCOUNT}\$"
fi

# SPNs to add
SPNS=("ldap/${BALANCER_HOST}")
# If hostname has no dot, try to add FQDN using realm (for clients that use FQDN)
if [[ "$BALANCER_HOST" != *.* ]]; then
    REALM=""
    if [[ -f /etc/samba/smb.conf ]]; then
        REALM=$(grep -E '^\s*realm\s*=' /etc/samba/smb.conf | sed 's/.*=\s*//' | tr -d ' \t' | head -1)
    fi
    if [[ -n "$REALM" ]]; then
        FQDN_SPN="ldap/${BALANCER_HOST}.$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"
        if [[ "$FQDN_SPN" != "ldap/${BALANCER_HOST}" ]]; then
            SPNS+=("$FQDN_SPN")
        fi
    fi
fi

added=()
skipped=()
errors=()

for spn in "${SPNS[@]}"; do
    if samba-tool spn list "$ACCOUNT" 2>/dev/null | grep -Fxq "$spn"; then
        skipped+=("$spn")
        continue
    fi
    errmsg=$(samba-tool spn add "$spn" "$ACCOUNT" 2>&1) || true
    if samba-tool spn list "$ACCOUNT" 2>/dev/null | grep -Fxq "$spn"; then
        added+=("$spn")
    else
        errors+=("Failed to add $spn: ${errmsg:-unknown error}")
    fi
done

# Report
for e in "${errors[@]}"; do
    echo "Error: $e" >&2
done
if [[ ${#errors[@]} -gt 0 ]]; then
    [[ ${#added[@]} -gt 0 ]] && echo "Added: ${added[*]}"
    exit 1
fi
if [[ ${#added[@]} -gt 0 ]]; then
    echo "Success. SPN(s) registered on $ACCOUNT: ${added[*]}"
fi
if [[ ${#skipped[@]} -gt 0 ]]; then
    echo "Already present (skipped): ${skipped[*]}"
fi
if [[ ${#added[@]} -eq 0 && ${#skipped[@]} -eq 0 ]]; then
    echo "No SPNs added and none skipped."
fi
exit 0
