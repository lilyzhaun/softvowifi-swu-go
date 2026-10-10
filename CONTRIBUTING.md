# Contributing

English and 简体中文 reports are welcome. Read the [README](README.md),
[source notes](PROVENANCE.md), [security policy](SECURITY.md) and
[code of conduct](CODE_OF_CONDUCT.md) first.

## Reports and evidence

Include the maintained commit, effective SWu/netlink replacements, Go/OS/kernel
and the exact protocol stage. Use synthetic vectors or loopback peers. EAP
success, Child-SA establishment, IMS registration and message/call delivery are
different evidence; do not combine them into one success claim.

Never upload real IMSI/ICCID/MSISDN/IMEI, AKA or IPsec keys, tokens, OTPs, message
bodies, complete configuration, raw captures or Wireshark key logs. Vulnerabilities
use the private reporting entry, not an issue containing exploit material.

## Pull requests

- Branch from current `main`; keep each protocol change small and attributable.
- First demonstrate the behavior with a direct regression. Prefer independently
  checked wire bytes/MACs and real loopback peers over a stub returning success.
- Preserve error propagation, authentication, replay/identity checks and the
  ownership of routes, policies, interfaces and sockets. Do not weaken a failing
  test, hardcode a carrier, or downgrade security to make an example work.
- Preserve module paths, pinned dependencies, copyright/license texts and unknown
  provenance. Third-party borrowing needs a source/version/license record.
- Format changed Go files and run:

  ```sh
  go test -p 1 -race -shuffle=on -count=1 -timeout=120s ./...
  go vet -p 1 ./...
  git diff --check
  ```

State the head/base, actual commands, failures/skips and compatibility impact.
Use Conventional Commits with your existing legitimate identity; no tool banners,
fabricated authors or generated attribution trailers. Do not rewrite shared history
or overwrite other contributors' work. Consumer pin updates are a separate action.

## Kernel and device testing

Default CI does not enable `ISSUE33_KERNEL_TEST`. Existing opt-in tests re-execute
with network-namespace guards and reject unsafe namespace access. Read those guards
before running privileged tests; never enable them blindly or weaken them for CI.

Use a disposable isolated namespace/VM, a bounded deadline and one cleanup owner.
Record kernel/capabilities and clear only owned links, routes/rules, XFRM and socket
state. Real SIM/carrier/Android experiments require separate consent and privacy
controls. They are not prerequisites for an unrelated documentation-only PR.
