# softvowifi-swu-go

[![CI](https://github.com/lilyzhaun/softvowifi-swu-go/actions/workflows/ci.yml/badge.svg)](https://github.com/lilyzhaun/softvowifi-swu-go/actions/workflows/ci.yml)

**English** · [简体中文](README.zh-CN.md)

A public maintained Go SWu client library for negotiating an IPsec tunnel to an
ePDG using IKEv2 and a caller-supplied SIM/USIM EAP-AKA provider. The original
module/import path remains `github.com/1239t/swu-go`.

This is an independent maintained snapshot, not an official upstream release or
full upstream mirror. It is **not a standalone Wi-Fi Calling application**: it
does not implement an IMS SIP registrar/client, SMS delivery, voice/media codecs,
Android SIM provisioning, carrier entitlement or account activation.

## Scope and maintenance

The retained code includes IKEv2 payloads, AKA processing, ESP sockets/data planes,
Linux network drivers and session lifecycle logic. Reviewed maintenance includes:

- COOKIE retries prepend the challenge without changing the original INIT offer.
- Final IKE_AUTH rejection notifications are preserved instead of being hidden by
  an incomplete-Child-SA error.
- Configured equipment identity is sent on an existing gateway request path,
  not unconditionally in the first IKE_AUTH.
- Initial ESP offers include a complete AES-CBC256/HMAC-SHA2-512 combination.
- Child-SA rekey/delete uses the local inbound SPI; policy/rule cleanup is scoped
  to the owning session rather than another session's table.

See the source and [maintenance notes](PROVENANCE.md), including
[COOKIE history](PROVENANCE.md#2026-10-10通用ike-cookie重试首载荷),
[final rejection handling](docs/ike-auth-final-reject.md),
[ESP offer coverage](docs/esp-sha512-offer.md) and
[equipment identity timing](docs/request-driven-equipment-identity.md).
Unit/loopback regressions are not proof of a live carrier session.

## Important limits

This library is not presented as a fully audited, unattended production VPN.
Do not infer complete responder certificate-chain/trust-anchor validation from
successful AKA or final AUTH processing. Resumption rejects unverified AUTH
material; the presence of ticket, fast-reauth, MOBIKE or rekey code does not prove
all lifecycle paths, seamless migration, long-term stability or every proposal
combination have been validated. Initial SHA2-512 offer coverage does not certify
SHA2-512 rekey interoperability. No carrier/device support matrix is promised.

Keep `DisableEAPMACValidation` and `EnableWiresharkKeyLog` disabled in normal use.
Disabling authentication checks or exporting secrets is not a compatibility fix.
Review the [security policy](SECURITY.md) before integrating with real subscribers.

## Requirements

- `go.mod` declares Go 1.24.0; CI uses Go 1.26 on Linux.
- A legitimate `sim.SIMProvider` implementing `GetIMSI`, `CalculateAKA` and `Close`.
  Read MCC/MNC and APN from your actual integration rather than guessing them;
  pass the correct two- or three-digit MNC explicitly.
- Linux kernel facilities appropriate to the selected data plane: XFRM interfaces
  for `xfrmi`, or TUN and userspace ESP for `tun`.
- Suitable privileges for network configuration and, where used, privileged UDP
  ports. Isolate driver testing from the host's live network.

Android/root/SIM access and complete rollback orchestration belong to the caller.

## Use the maintained revision

In an existing Go module, explicitly pin both SWu and its netlink dependency:

```sh
go mod edit -require=github.com/1239t/swu-go@v0.0.0-20261009235012-6fb3163569ae
go mod edit -replace=github.com/1239t/swu-go=github.com/lilyzhaun/softvowifi-swu-go@v0.0.0-20261009235012-6fb3163569ae
go mod edit -replace=github.com/iniwex5/netlink=github.com/lilyzhaun/softvowifi-netlink@v0.0.0-20260915075719-be8893d91893
go get github.com/1239t/swu-go/pkg/swu@v0.0.0-20261009235012-6fb3163569ae
go list -m -json github.com/1239t/swu-go github.com/iniwex5/netlink
```

Imports still use `github.com/1239t/swu-go/...`. A consuming **main module does
not inherit dependency `replace` directives**, so the netlink replacement above
is required even though this repository already has one in its own `go.mod`.
The example is a reproducible maintained code pin, not a moving `main` dependency.
Fetching the actual `pkg/swu` package also records the transitive requirements
and checksums needed to compile a fresh consumer; downloading only the two
replacement module archives is not sufficient for that consumer's `go.sum`.

## Embedding API example

This is a compilable integration helper, **not a runnable fake-SIM demo**. The
caller supplies a real authorized provider, correct subscription parameters and
a context whose deadline/lifetime matches its application. Driver-enabled
`Connect` performs real network operations. This maintenance validates the helper
by compilation only; default CI does not execute it against real subscribers.

```go
package integration

import (
	"context"

	"github.com/1239t/swu-go/pkg/sim"
	"github.com/1239t/swu-go/pkg/swu"
)

func OpenTunnel(ctx context.Context, provider sim.SIMProvider,
	epdg, apn, mcc, mnc string) (*swu.Session, error) {
	cfg := &swu.Config{
		EpDGAddr:      epdg,
		EpDGPort:      500,
		APN:           apn,
		MCC:           mcc,
		MNC:           mnc,
		SIM:           provider,
		EnableDriver:  true,
		DataplaneMode: "xfrmi",
		ReplayWindow:  128,
	}
	session := swu.NewSession(cfg, nil)
	if err := session.Connect(ctx); err != nil {
		session.Shutdown()
		return nil, err
	}
	return session, nil
}
```

Retain the session while it is in use. On exit, use its shutdown/lifetime APIs,
close provider resources owned by your integration and verify cleanup of owned
interfaces, sockets, routes/rules and XFRM state. A canceled context or a return
from `Shutdown` alone is not evidence that every kernel resource is gone. Tunnel
establishment is not SIP registration, message delivery or an audible call.

## Develop and test

```sh
git clone https://github.com/lilyzhaun/softvowifi-swu-go.git
cd softvowifi-swu-go
go test -p 1 -race -shuffle=on -count=1 -timeout=120s ./...
go vet -p 1 ./...
```

Default CI uses synthetic vectors and local peers, not a real SIM, ePDG or phone.
Kernel opt-in tests remain disabled (`ISSUE33_KERNEL_TEST` is not enabled); their
skips are intentional coverage limits, not kernel acceptance. Privileged testing
requires the documented isolation guards and explicit cleanup ownership. See
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[issue templates](https://github.com/lilyzhaun/softvowifi-swu-go/issues/new/choose).

## License and provenance

The original [MIT LICENSE](LICENSE) and `Copyright (c) 2026 iniwex5` are unchanged.
The exact original upstream revision/version remains **unknown**; no local import
commit or current GitHub repository is substituted for that missing provenance.
See [PROVENANCE.md](PROVENANCE.md). Dependencies retain their own licenses and
source qualifications, including [softvowifi-netlink](https://github.com/lilyzhaun/softvowifi-netlink).

The [historical README](docs/README-imported.md) is preserved as context. Its old
module paths, private status and broad completeness/0-RTT claims are not current
installation instructions or validated capability statements.
