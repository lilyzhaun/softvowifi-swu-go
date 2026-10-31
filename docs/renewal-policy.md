# Session renewal policy

`Config.RenewalPolicy` controls the existing Session consumers independently of
proposal selection. It is a Go API, not an operator configuration format or a
set of recommended carrier values. `Config.ValidateRenewalPolicy()` performs the
same side-effect-free preflight as Session startup and returns the fixed
`ErrInvalidRenewalPolicy` error for an unsupported policy.

## Capture and compatibility

The complete group is copied at first protocol use, before Connect opens a
socket. Later caller edits require a new Session. Each nested struct is a value;
there are no shared caller-owned slices or maps. Callback fields outside this
group retain their existing lifecycle.

Nil retains the existing 1500-second IKE and 1800-second Child rekey intervals,
whole-second early jitter in `[0, 30)` seconds, zero kernel SA lifetime limits,
20-second NAT keepalive, 150-second NAT-to-DPD margin and `DefaultRetryConfig()`.
Legacy `ReauthInterval` and caller-started DPD retain their meaning. These are
compatibility facts, not newly imported OEM defaults.

An explicit group has these independent members:

| Member | Consumer |
|---|---|
| `IKE` / `Child` (`SALifetimePolicy`) | Soft lifetime schedules that SA's rekey, minus early-only `RekeyJitter`. Hard lifetime retires its current generation even if the exchange worker is waiting for a response. |
| `Reauthentication` | Local authentication deadline; zero disables only this local trigger. An earlier protected AUTH_LIFETIME still wins and neither IKE nor Child rekey renews authentication. |
| `DPDInterval` | Authenticated inbound-idle detection; zero disables periodic DPD. Explicit policy starts it after establishment; a caller's additional `StartDPD` does not create a second worker. |
| `NATKeepaliveInterval` | The NAT-detection path's outbound-idle sender; zero disables keepalive. It does not force NAT detection. |
| `NATKeepaliveDPDMargin` | Extra outbound inactivity before NAT keepalive escalates to DPD. Zero disables this escalation, not ordinary DPD. |
| `Retransmission` (`RetryConfig`) | The actual initial and protected request window, including identical encoded packet/fragment retransmission and exhaustion. |

## Lifetimes and validation

Each explicit SA requires positive soft/hard lifetimes with `hard > soft` and
`jitter >= 0`. Whole seconds are required for all three fields. The earliest
rekey (`soft - jitter`) must be at least the existing 30-second local cooldown.
Jitter is uniformly early-only in whole seconds below its configured bound;
zero selects exactly the soft lifetime. No invalid values are swapped, clamped,
or replaced with defaults.

Both Child directions receive the same captured soft/hard kernel limits on
initial setup, local/peer rekey and MOBIKE updates. Only successful replacement
renews that SA's local hard deadline. Failed or duplicate exchanges, MOBIKE and
the other SA's rekey do not. Retired IKE/Child overlap is capped by the original
hard deadline, including rejection of retired inbound Child keys while cleanup
is pending. Local hard expiry is reported as `ike_lifetime_expired` or
`child_lifetime_expired`; kernel events retain `kernel_hard_expire`.

Initial local hard deadlines begin after authenticated establishment, before
dataplane setup and readiness callbacks. Kernel limits use the kernel's SA add
time; the local deadline can therefore be earlier after slow setup. Expired IKE
keys cannot be used for a teardown Delete; ordinary cancellation still attempts
the existing graceful Delete while the key is valid.

The liveness/authentication intervals and margin must be nonnegative. Retry
count is 0–32 (retransmissions after the first send), initial delay is positive,
optional maximum delay is zero or at least the initial delay, and the multiplier
is finite and at least 1. Per-delay and accumulated-budget overflow is rejected.
TaskManager retains its existing half-second scheduling resolution; a duration
is not a promise of sub-millisecond wire timing.

The maximum retry delay is applied before converting a multiplied delay back
to `time.Duration`, so even a large finite multiplier with a valid cap cannot
wrap into a negative deadline. The real-UDP capture test synchronizes caller
edits with the transport-factory boundary, rather than treating external UDP
receipt as a Go memory synchronization event.

## Evidence boundary

The initial regression observed ignored inputs in real Connect/UDP, protected
Child rekey installation and the actual NAT timer sender. Additional tests drive
real timers using Go's standard `testing/synctest`, inspect authenticated rekey
and DPD packets, and cover generation ownership, replay, failure, cancellation
and AUTH_LIFETIME. Virtual-time host evidence is not natural device time.
These virtual-clock test files declare `go1.25`; the existing CI uses Go 1.26
and executes them. Production keeps the Go 1.24 module floor. The ordinary UDP,
validation, rekey installation, kernel and retained authentication tests do not
depend on the conditional files; Go 1.24 does not run the virtual-clock cases.
The kernel test is opt-in and refuses the parent network namespace. Test and CI
outcomes must be taken from the current review, not inferred from these test
descriptions. No device, carrier, business or long-term acceptance is implied.
