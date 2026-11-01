# Captured IKE identity policy

`Config.IdentityPolicy` is optional. `NewSession` copies its two type choices
and optional peer identity bytes. Later edits require a new Session; an invalid
captured policy returns `ErrInvalidIdentityPolicy` before opening a transport.
`Config.ValidateIdentityPolicy()` checks that same policy without SIM/network I/O.

## Independent inputs

| Input | Supported forms | Value source |
|---|---|---|
| `LocalIDType` | `ID_RFC822_ADDR`, `ID_KEY_ID` | Existing SIM-derived NAI or caller-supplied temporary identity |
| `RequestedIDrType` | `ID_FQDN`, `ID_KEY_ID` | Existing `Config.APN` |
| `Peer` | Optional exact `Type` + `Data` | An independent caller constraint on the received responder ID |

An explicit policy supplies both types; zero is not an implicit default.
A nil policy preserves the existing RFC822 local identity and FQDN APN request.
These are native library types, not a parser for another client's settings.

`Peer.Type` accepts FQDN, RFC822, KEY_ID, IPv4 and IPv6. Text is ASCII, has no
spaces/control characters, and uses DNS labels for the FQDN/realm. KEY_ID data
is opaque; IP identities use exactly four or sixteen network-order bytes. All
data is nonempty and limited to 1024 bytes, with normal DNS label/name limits
for text domains. Unsupported DER/general-name identities are rejected.

Matching is exact type and bytes: no wildcard, DNS lookup, case folding, or
automatic conversion between APN, the ePDG endpoint and peer identity. A nil
`Peer` adds no peer pin and retains the existing AUTH requirement. A matching
ID is not itself authentication or certificate-chain validation.

## Authentication and lifecycle

The existing NAI/APN source paths remain in use when AUTH1 is constructed.
This API captures policy, not a replacement static local subscriber identity.
The original IDi body remains frozen independently of subsequent inner EAP
Identity selection; EAP keys use the actual method identity. Expected-peer
matching ignores RESERVED semantics, while final AUTH still authenticates the
entire received IDr body, including RESERVED bytes.

The constraint is applied on receipt before processing an accompanying EAP
request, and when an IDr first appears in the final authenticated response.
Mismatch returns the existing typed IKE AUTH failure with the fixed reason
`peer_identity`, without emitting identity values or committing Child state.
The same captured constraint remains in effect across the Session's attempts.

Existing Config ownership and late-installed lifecycle callbacks remain intact;
the policy copy does not freeze the entire Config. Temporary-identity credential
storage/rotation remains the caller's existing responsibility. This change does
not add a persistence service or claim complete fast-reauth interoperability.

## Verification and sources

Normal UDP Connect regressions first demonstrated that the old code ignored
the new type choice and peer constraint (two behavior failures, one compatible
control pass). The policy and original identity/AUTH regressions then passed
97 test/subtest events with race/shuffle enabled. Tests include independent
initiator/responder AUTH, inner permanent Identity following an outer temporary
identity, captured-policy aliasing, invalid input before transport, and final
peer matching with nonzero RESERVED bytes. Full-library results belong to the
fixing PR's actual CI; these peers are not SIM/carrier/device acceptance.

References are RFC 7296 §§2.15, 2.16 and 3.5 (October 2014; IETF Trust Legal
Provisions), existing maintained code and Go standard-library APIs. No external
client code, settings format, defaults or operator parameters were copied.
