# Security policy

## Scope

Maintenance targets current `main` and explicitly reviewed fixes, not a published
LTS window. Consumers pinning older revisions must separately adopt fixes.
No response-time SLA, full protocol audit or cross-carrier/device guarantee is
promised. See [README limits](README.md#important-limits) and
[PROVENANCE.md](PROVENANCE.md).

## Private reporting

Use GitHub's **Security → Report a vulnerability**:

https://github.com/lilyzhaun/softvowifi-swu-go/security/advisories/new

Do not publish unpatched exploit details in issues or PRs. If the entry is
temporarily unavailable, use GitHub's support/reporting tools rather than a public
sensitive-data dump. Coordinate disclosure timing with the maintainer.

Provide the affected commit and dependency replacements, impact, trust/privilege
assumptions and a minimal synthetic or isolated-peer reproduction. Never attach
live subscriber identifiers, SIM/AKA material, passwords, tokens, OTPs, IPsec keys,
full device configuration, message bodies, raw captures or key logs—even to a
private advisory when synthetic data suffices.

## Integration hazards

- Do not treat AKA success as complete responder certificate-chain validation.
- Do not enable `DisableEAPMACValidation` or export Wireshark secrets as a normal
  deployment or compatibility measure.
- Session tickets/reauthentication caches are sensitive credentials; do not put
  them in Git, public logs, diagnostic bundles or issues.
- Privileged driver operations must have isolated scope and explicit cleanup
  ownership. Do not flush another session's XFRM or routing state.
- Local unit/loopback CI cannot establish live-network, device or long-term safety.
