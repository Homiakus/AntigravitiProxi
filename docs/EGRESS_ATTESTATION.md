# Runtime egress attestation

## Goal

Agent Tunnel must not treat a correct-looking configuration as proof that Antigravity actually uses the selected network path. The assurance model separates four evidence layers:

1. **Process discovery** — inventory the live Antigravity process tree and surface unknown descendants.
2. **Route decision evidence** — query the authenticated loopback sing-box 1.14 connection tracker and observe source endpoint, process path and selected outbound (`vpn-direct` or an unexpected outbound).
3. **PID/socket ownership evidence** — join the connection source endpoint with operating-system socket ownership and prove that the live connection belongs to a PID from the discovered Antigravity process tree.
4. **External egress evidence** — send a probe through `local-mixed -> vpn-direct` and ask an external observer which source IP it sees. Query the same observer without an HTTP proxy as a `system-direct` control path.

No single layer is sufficient by itself. The intended production invariant is:

```text
Antigravity PID
        -> owned live socket/source endpoint
        -> sing-box live connection
        -> outbound = vpn-direct
        -> vpn-direct bind_interface = selected VPN
        -> external observer sees VPN egress
```

The `system-direct` comparison is negative/control evidence. A different observed IP is strong evidence that the two policies have distinct external consequences. The same IP is **not** automatically a failure because a host-wide VPN can legitimately make both paths share one public NAT address.

## Current implementation

`internal/proxy/observability.go` exposes `RuntimeConnections` and `AttestAgentRoutes`. Runtime connection evidence includes `source`, `process`, `outbound`, `destination`, `inbound` and `network`. The connection tracker is available only on an authenticated loopback API service. The API secret is randomly generated, never returned by the HTTP control plane and never logged.

On Unix-like systems the persisted API secret is written as `0600` and this is regression-tested. On Windows, POSIX `FileMode` bits are not valid ACL evidence: NTFS access is inherited from the per-user application-data directory and a file may report `0666` through Go while still being ACL-restricted. Native Windows security-descriptor verification/hardening remains a separate security task; tests must not pretend POSIX mode bits prove a Windows DACL.

`internal/proxy/pid_attestation.go` exposes `AttestAgentPIDRoutes`. The caller supplies PIDs from the live Antigravity process tree. Every live connection is joined against OS socket ownership instead of assuming that a familiar executable path is sufficient identity evidence.

Platform ownership backends are deliberately separate:

- Linux: source endpoint -> `/proc/net/tcp{,6}` or `/proc/net/udp{,6}` -> socket inode -> `/proc/<pid>/fd`;
- Windows: exact local source endpoint -> `netstat -ano` PID -> candidate Antigravity PID set;
- unsupported platforms fail closed.

An idle candidate PID with no live socket is not treated as a routing failure because there is no current egress to attest. Ambiguous ownership, an unexpected outbound or an Antigravity-looking connection that cannot be joined to a candidate PID remains incomplete/degraded evidence and is never promoted to verified assurance.

`internal/proxy/egress.go` exposes `AttestPublicEgress`. Production probes currently use two independent observers:

- `https://api.ipify.org/`
- `https://www.cloudflare.com/cdn-cgi/trace`

The observers are queried concurrently through the managed local proxy. At least one valid IP response is required for external egress evidence to be `available`. If more than one valid VPN address is observed, all are retained because destination-dependent NAT/egress is legitimate and disagreement alone is not treated as failure.

After the first successful VPN-path observation, the same provider is queried with an HTTP transport whose `Proxy` is explicitly `nil`. This prevents inherited `HTTP_PROXY` / `HTTPS_PROXY` settings from contaminating the control path.

`internal/app/attestation.go` composes process-tree, route-decision, PID/socket and external-egress evidence into an assurance state: `idle`, `partial`, `verified` or `degraded`. External observer unavailability is classified as incomplete evidence rather than proof of a routing defect; unexpected or ambiguous routing evidence is degraded.

The composed evidence is exposed read-only at `GET /api/attestation`. The endpoint reports whether external evidence came from cache and includes `egress_fresh_until`. The Web UI renders the assurance state, attributable PID ratio, egress availability and evidence age instead of conflating transport readiness with strong route verification.

## Bounded external-evidence cache

Public observers are not queried on every UI refresh. `internal/app/attestation_cache.go` keeps a short-lived in-memory cache keyed by the managed sing-box PID and selected VPN interface:

- successful external evidence: **15 s TTL**;
- unavailable/failed external evidence: **3 s TTL**.

A different managed PID or VPN interface cannot reuse the entry. `egress_cached` and `egress_fresh_until` make this explicit to callers. The cache is intentionally memory-only; public IP evidence is not persisted.

The key is an identity/freshness guard, not a proof that the VPN did not reconnect beneath the same interface. Therefore successful evidence remains deliberately short-lived and can never become durable health state.

The cache is also explicitly invalidated on data-plane lifecycle boundaries instead of relying only on the key and TTL. Current invalidation points include data-plane configuration commits, SAFE/Agent Tunnel mode transitions, Agent Tunnel start/stop, explicit managed-data-plane stop, restart-before-launch and startup rollback. Each lifecycle invalidation publishes a local event so a state transition is auditable in the UI event stream.

## Privacy contract

Public IP evidence is sensitive operational data. `AttestPublicEgress` returns it only to the local caller and does not persist or log the address. Diagnostic/support export must pass through the centralized redaction policy before this evidence is ever included in a bundle. This is part of R-019.

The probe sends no account identifiers, cookies, OAuth tokens, Antigravity payloads or user content. It performs only a small `GET` to a public source-address observer.

## Fail-closed behavior

External egress attestation is unavailable when:

- Agent Tunnel is not running;
- managed mixed-listener ownership is not proven;
- all configured observers fail;
- an observer returns a non-2xx response;
- an observer response does not contain a syntactically valid IPv4/IPv6 address.

PID-route evidence remains incomplete when:

- no candidate Antigravity PID is supplied;
- a source endpoint cannot be found in the OS socket tables;
- more than one candidate PID ambiguously owns the same evidence;
- the operating system cannot prove socket ownership;
- the observed outbound is not `vpn-direct`.

Observer unavailability is evidence unavailability, not proof that the VPN route is wrong. Therefore this layer must not be silently converted into a routing failure. Higher-level orchestration should report partial assurance and retry with bounded backoff.

## Deterministic Linux CI proof

The privileged Linux `netns` fixture has two independent L3 uplinks:

- `vpn0` source `10.250.0.2`;
- `sys0` source `10.251.0.2`.

A sink namespace hosts a source-address observer at `203.0.113.10`. The runtime test queries the exact same observer through `vpn-direct` and `system-direct` and asserts that the externally observed sources are `10.250.0.2` and `10.251.0.2` respectively. This proves that the selected outbound label has a real packet-path consequence, not merely a config or connection-tracker label.

The fixture also starts a real Antigravity-named probe and deliberately keeps its TCP connection open. While that socket is live, the test joins:

```text
probe PID
 -> /proc/<pid>/fd socket inode
 -> /proc/net/tcp source endpoint
 -> sing-box connection source endpoint
 -> outbound vpn-direct
 -> remote observer source 10.250.0.2
```

This PID-level proof passes in the privileged Linux runtime job together with TUN startup/cleanup, PID/path routing, crash recovery, reserved route/rule ownership and authenticated connection-tracker access.

## Windows evidence

Windows now has two levels of native-runner evidence:

1. parser fixtures verify exact endpoint matching, candidate filtering, IPv4/IPv6 parsing and ambiguous candidate ownership;
2. a Windows runner opens a real TCP socket and verifies that `netstat -ano` attributes that live local endpoint back to the creating process PID.

This proves the current ownership backend behaves correctly on Windows itself, but it is still weaker than the Linux end-to-end Agent Tunnel fixture because it does not yet run the complete privileged TUN + sing-box + remote-observer chain on Windows.

## Remaining assurance gaps

Linux now has deterministic end-to-end PID/socket/outbound/external-egress proof. Windows has real socket-to-PID runtime evidence but still needs a complete Agent Tunnel runtime fixture before equivalent end-to-end assurance can be claimed there.

Next steps:

- add a privileged Windows Agent Tunnel runtime fixture with a controlled remote observer;
- migrate Windows ownership from `netstat -ano` parsing to native IP Helper APIs if it materially improves determinism and failure classification;
- add explicit Windows security-descriptor verification/hardening for persisted secrets and sensitive runtime files;
- keep `verified` as a separate assurance dimension instead of overloading basic TUN health;
- block strong assurance on unknown helpers, ambiguous ownership or unexpected outbound;
- add independent IPv4/IPv6 and UDP/QUIC evidence before closing R-005.
