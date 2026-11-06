# Explicit interface MTU

## Current status

`Config.RequireInterfaceMTU` is an optional SDK field. Its zero value is
`false`. `NewSession` captures the flag and `TUNMTU`; later caller edits do
not change either value for this Session, including legacy callers.
The implementation has focused and isolated Linux 6.8 bootstrap validation.
The complete maintenance race/shuffle/count1 regression and vet also passed;
this change's CI is still pending. This is not Android, carrier, or long-term
validation.

The original consumer was tested before the strict implementation: a real
TUN setup call swallowed the setter error, continued address and route setup,
and did not close its TUN. The strict test failed; the same numeric MTU and
setter error passed the legacy compatibility control. That RED is retained.

## Contract

- `RequireInterfaceMTU: false` preserves best-effort compatibility, including
  existing default-MTU and IPv6 minimum behavior. A nonzero `TUNMTU` alone
  does not opt into strict application.
- `RequireInterfaceMTU: true` requires an explicit positive `TUNMTU` and a
  supported interface dataplane. A later edit of the caller's configuration
  must not change this Session's captured strict request.
- TUN and XFRM interface setup must propagate a failed setter before address
  or route configuration, negotiated-security publication, and `OnReady`.
  Successful setter return means the operation was accepted; it is not an
  independent kernel read-back or a guarantee against subsequent changes.
- A failed setup must release only its owned resources. Cleanup errors must
  preserve the original setter error and pending ownership for explicit
  cleanup; they must not be converted into success or a global flush.
- Strict requirements are unsupported without a driver or in `netstack`
  mode and must be rejected before transport use. The current netstack path
  has no interface MTU setter and does not use the TUN fragmentation loop.
  Best-effort callers retain their existing behavior.
- A strict request must not be silently replaced by another value or by a
  different dataplane to get past an unsupported operation.
- If an allocated IPv6 address requires the 1280 minimum, a smaller strict
  request is rejected before interface creation. Legacy callers retain the
  original minimum clamp. The SDK does not adopt a caller application's
  narrower MTU range.

The internal flag is not another user policy value, a negotiated MTU, an
OEM-derived setting, or a request to add monitoring or retry machinery.
Consumers that expose an explicit interface-MTU policy must opt in based on
the presence of that policy, not infer presence from a default numeric value.

## Validation and limitations

Focused tests exercise successful setup, captured requests, pre-transport
rejection, IPv6 minimum behavior, and failed-close ownership. The independent
AKA/AUTH peer confirms that a strict setter failure closes its TUN without
publishing ready or negotiated security. Legacy setter failure and strict
success reach ready once and configure their allocated address and P-CSCF
route. A valid response without P-CSCF reaches ready without a direct route.
The first success-control assertions incorrectly required a route despite
omitting P-CSCF and using a full-range TS; that failed run is retained. The
fixture now covers both legal CP shapes without changing production routing.

The opt-in kernel test passed once in a private Linux 6.8.0-31 network
namespace. It retains the real socket, XFRM manager, owned SA/SP/interface and
an independent foreign canary, injecting only the setter failure. Strict
failure, legacy failure, and strict success all pass. The success case reads
the requested MTU back; actual owned-state drift blocks cleanup, retains the
pending link, and permits explicit cleanup after exact state restoration.
Full canary structures remain unchanged and final owned inventories are empty.
This kernel did not expose SA direction metadata; that remains unverified,
not a Linux 7 direction result. The direct-route fixture is not policy-routing
validation. Bootstrap read-back is not a guarantee against external changes,
MOBIKE effects, Android behavior, or long-term MTU stability.

The complete non-privileged regression passed 529 parent and 1080 child tests,
with 18 parent and 12 child opt-in skips retained. The nine interface-MTU
parents and 19 children all executed and passed. The `sim` package has no
test files and is not counted as a passed test. Kernel cases skipped in that
run; the private-namespace result above is separate, not CI coverage.
