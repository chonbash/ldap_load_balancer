# LDAP Controls Requirements (RFC 4511)

## Scope

Request controls: already parsed and forwarded in proxy. Response controls: encode optional [0] IMPLICIT SEQUENCE OF Control in LDAPMessage so backend response controls can be passed through when LB generates responses (e.g. persistent search, error responses).

## Control Format (RFC 4511)

Control ::= SEQUENCE { type LDAPOID, critical BOOLEAN DEFAULT FALSE, value OCTET STRING OPTIONAL }

## Controls in Use

- Sync Request (RFC 4533): already parsed; proxy forwards. Response controls: Sync State/Done when we generate entries.
- Paged Results (RFC 2696): parse request value for handler; in proxy, forward as-is. Response control: cookie in Search Result Done.
- Unknown critical control: return appropriate error (e.g. unavailableCriticalExtension) when not forwarding.

## Implementation

- encode_ldap_message: when message.controls is Some and non-empty, append [0] 0xA0 and encoded SEQUENCE OF Control.
- Parsing: already supported. No change to request path.
