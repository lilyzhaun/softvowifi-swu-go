# Remote address-family selection

Maintainer: `lilyzhaun`. Branch: `feat/remote-address-family-20261101`.
Baseline: `9031f8af891de254447b15365b220b1c62828b00`.

`Config.RemoteAddressFamily` is an optional `ipsec.AddressFamilyPolicy`, captured
by `NewSession`. It controls the built-in `Connect` transport's remote candidate
selection, including a fresh connection after a redirect:

| Value | Selection |
|---|---|
| empty | Retained compatibility behavior, IPv4 first when available |
| `prefer-ipv4` | First compatible IPv4, otherwise compatible IPv6 |
| `prefer-ipv6` | First compatible IPv6, otherwise compatible IPv4 |
| `ipv4-only` | Reject a literal or DNS result with no compatible IPv4 |
| `ipv6-only` | Reject a literal or DNS result with no compatible IPv6 |

DNS sockets still use the actual DNS endpoint's family and the caller's selected
network. IPv6-only ePDG selection therefore does not forbid an IPv4 DNS server.
`SocketControl`, `SourceIP`, context cancellation, observer identity and DNS TCP
fallback keep their existing roles. No resolver or network escape is added.
Unbound callers may use the default resolver; bound hostname lookups still need
an explicit DNS endpoint. Unknown values reject before opening a socket.

The lower-level `ipsec.NewSocketManagerWithAddressFamily` accepts the same policy.
Existing constructors delegate with the compatibility value. A UDP socket still
rotates only within its selected family; preference is not simultaneous dialing,
cross-family retry, reachability detection or a change to authentication policy.

An explicit policy rejects custom `TransportFactory` and live `UpdateAddresses`
with `ErrAddressFamilyPolicyTransport`: those paths do not currently accept this
selection contract. This avoids silently ignoring a caller's restriction. The
empty policy leaves their existing behavior unchanged. This change does not
claim new MOBIKE support, home/roaming decisions, PLMN ordering, APN selection or
local/remote IKE identity configuration.

Direct loopback regressions exercise both DNS families, actual IKE_INIT delivery
and NAT source hashes, constructor-time capture, strict rejection before dialing,
preference versus strict filtering and the default-resolver branch. Their result
must be read from the current PR's CI; they are not live carrier/device evidence.

Implementation is based on the retained socket/resolver code and Go `net` APIs;
no third-party implementation, operator settings or protocol defaults were
imported. Existing module paths, dependency pins, MIT copyright and unknown
upstream provenance remain unchanged.
