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

`internal/proxy/observability.go` exposes `RuntimeConnections` and `AttestAgentRoutes`. Runtime connection evidence includes `source`, `process`, `outbound`, `destination`, `inbound` and `network`. The connection tracker is available only on an authenticated loopback API service. The API secret is randomly generated, stored with owner-only permissions, never returned by the HTTP control plane and never logged.

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

## Remaining assurance gaps

Linux now has deterministic end-to-end PID/socket/outbound/external-egress proof. Windows has the implementation for exact local endpoint -> `netstat -ano` -> candidate PID correlation and cross-build coverage, but still needs a privileged/real-network Windows runtime fixture before the same assurance level can be claimed there.

The next architecture step is not another routing heuristic. It is **continuous assurance orchestration**:

- expose the composed attestation through the local control-plane API and Advanced UI;
- cache evidence with timestamps/expiry rather than probing public observers on every status refresh;
- make `verified` a separate assurance dimension instead of overloading basic TUN health;
- block a strong “verified egress” state on unknown helpers, ambiguous ownership or unexpected outbound;
- add a Windows runtime fixture and migrate Windows PID ownership from command parsing to native IP Helper APIs if this materially improves determinism;
- add independent IPv4/IPv6 and UDP/QUIC evidence before closing R-005.
