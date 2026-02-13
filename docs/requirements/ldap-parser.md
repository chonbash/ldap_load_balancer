# LDAP Protocol Parser Requirements (RFC 4511)

## Scope

Full LDAP v3 message parser: all request/response operations with strict tag and length validation. Filter is parsed into a structured type (AST) per RFC 4511.

## Request/Response Pairs

- BindRequest/BindResponse
- SearchRequest (with structured Filter) / SearchResultEntry, SearchResultDone
- ModifyRequest/ModifyResponse
- AddRequest/AddResponse
- DelRequest/DelResponse
- ModifyDNRequest/ModifyDNResponse
- CompareRequest/CompareResponse
- ExtendedRequest/ExtendedResponse
- UnbindRequest (no response)
- IntermediateResponse

## Filter (RFC 4511)

Structured representation: and (SET OF), or (SET OF), not, equalityMatch, substrings, greaterOrEqual, lessOrEqual, present, approxMatch, extensibleMatch. Parser must handle nested filters and unknown/context-specific tags (e.g. store as opaque bytes or skip with error for critical path).

## Compatibility

- Real clients: OpenLDAP, AD, ldapsearch. Accept common tag variants (e.g. simple bind [0] vs [APPLICATION 1]).
- Proxy mode: raw bytes forwarded unchanged; parser used for persistent search, StartTLS, and error responses. Filter structure used where we need to interpret (e.g. logging, future routing).

## Validation

- Reject invalid tags for each CHOICE. Reject truncated or overlong length. Optional: reject trailing bytes after full message parse.
