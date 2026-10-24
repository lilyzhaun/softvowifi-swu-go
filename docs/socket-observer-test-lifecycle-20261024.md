# Socket observer regression fixture lifecycle

## Scope and baseline

- Maintainer: lilyzhaun; branch `test/socket-observer-lifecycle-20261024`, based on `main` commit `ca3e54b3b214bee265ee057709d0d0562ade2315`.
- Investigate the real-loopback occupied-port observer regression without changing production code, protocol timing, assertions, module paths, licenses, or retained-source provenance.
- First obtain a direct failure with useful synthetic diagnostics. Only then make a minimal test-synchronization correction if the evidence supports it. No device, carrier, credential, or packet-capture data is involved.

## Initial observation

The current test gives an entire `Session.Connect` call a 100 ms context budget before asserting a successful write observation. This budget includes socket setup, retry, packet construction, and dispatch before the first write. The observed failure reports one successful dial, one address-in-use observation, and no successful write observation; the original assertion does not retain the returned connect error.

This is not yet a proven root cause. It does not establish that production observation is broken or that the failure is flaky. Preserve actual sockets, occupied-port retry, caller context checks, event counts, and failure propagation in any direct regression.

## Validation status

The test-only diagnostic input adds a delayed occupied-port startup case and retains the returned connect/context errors. It keeps the original 100 ms context and every existing socket, source, context-value, event-count, and error assertion. The 150 ms controlled startup intentionally outlives that existing pre-write budget; its actual outcome has not been observed yet.

## Controlled RED

One focused race/shuffle/count=1 run on Go 1.26.10 with GOMAXPROCS=1 passed the original direct and occupied-port cases. The delayed occupied-port case failed with `dial=1 in-use=1 sent=0` and an expired caller context. The returned connect error was classified as other; its exact value was not retained. This establishes a fixture precondition problem under controlled startup delay, not the unique cause of a previous uninstrumented failure or proof that production has no defects.

The maintained input digest was `dfb72e2a4c744cca6ea8969d32fc7245847dc4bf6857133933bbca12d9c27cc5`. The command targeted only this parent test and its three cases. This repository resolved x/sys v0.40.0; the consumer graph can differ.

## Minimal correction pending validation

The test now cancels its caller context on the successful write observation it is asserting. A separate five-second deadline bounds a missing-event failure, and an explicit cancellation assertion ensures that hitting that deadline cannot pass. All original event-count, source-address, caller-context, actual occupied-port retry, and non-successful-session assertions remain. The controlled delayed case remains in the matrix.

Production code, protocol timers, module files, and consumer pins are unchanged.

## Focused GREEN

One race/shuffle/count=1 run on the corrected input passed all seven observer parent tests and ten subtests across swu and ipsec, with no failures or skips. This includes the delayed occupied-port case, both original startup cases, control-error propagation, real DNS framing and cancellation/error cases, and real outer UDP checks. The delayed case passed in 0.16 seconds rather than failing with the old pre-write deadline.

The corrected source digest was `756c1647bff27710446fd9814a7aae4747cb549eca30b932a2b1d7d8fcdca95d`; only the test file differed from the RED input. Go 1.26.10 and GOMAXPROCS=1 were used. Successful non-verbose diagnostics do not provide exact per-case event counts or connect errors, so those are not invented.

## Complete-library input correction

The first complete-library run failed four tests at reads of the existing `testdata/eap_only_auth1_before.hex` fixture: the execution archive omitted non-Go testdata. Observer regressions still passed, but the full run is not a success and vet was not executed. The archive preparation error is not a demonstrated production regression.

The corrected archive includes the complete tracked package tree and testdata without changing any fixture, Go source, or assertion. It adds the two tracked testdata files to the original 262-file input, with every original file unchanged.

## Complete-library validation

One corrected-input race/shuffle/count=1 run on Go 1.26.10 / GOMAXPROCS=1 passed 420 parent tests and 811 subtests, with no failures. Fourteen parent tests and twelve subtests retained their explicit isolated-kernel opt-in skips; they are not counted as passes. Seven test packages passed and one package had no tests. The four previously blocked fixture-reading tests and all observer cases passed in this run.

`go vet -p 1 ./...` then actually ran and exited zero. The complete input digest was `5532e04852ded8d2c06acdb919e6b536ec09ca329acc3d46befb84f6346482de`; tests and vet used that same verified 264-file input. The previous failed archive run remains a separate result, not retroactively successful.

Hosted PR CI with its own GOMAXPROCS=2 environment is still pending. No release or consumer adoption is claimed, and the original uninstrumented failure's unique cause remains unproven.
