# BER Encoding/Decoding Requirements (RFC 4511 / X.690)

## Scope

Full BER support for LDAP v3 protocol as used in RFC 4511. Backward compatibility with existing parser must be preserved.

## Required Features

- **Length**: Short form (0–127), long form (128–2^32-1). Indefinite length: support reading where applicable (e.g. optional in decoders); LDAP uses definite length for messages.
- **Tags**: Single-byte (0–30) and multi-byte (high tag number ≥ 31) per X.690.
- **Universal types used in LDAP**: BOOLEAN (1), INTEGER (2), OCTET STRING (4), NULL (5), OID (6), ENUMERATED (10), SEQUENCE/SEQUENCE OF (16). Context-specific and application tags as in RFC 4511.
- **OID**: Read and write for control OIDs and attribute type names.
- **GeneralizedTime**: Optional; add if needed for LDAP schema/controls. Not required for minimal production set.

## Boundaries

- Only types and encoding rules actually used in LDAP messages, controls, and filters.
- No CER/DER restrictions (BER allows multiple encodings).
- Maximum length field: 4 bytes (length value up to 2^32-1).

## Compatibility

- Existing `BerReader`/`BerWriter` single-byte tag APIs remain. New multi-byte tag APIs are additive.
- All current unit tests and integration scripts (01–17) must continue to pass.
