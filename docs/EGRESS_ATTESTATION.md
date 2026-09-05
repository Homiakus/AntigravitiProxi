# Runtime egress attestation

## Goal

Agent Tunnel must not treat a correct-looking configuration as proof that Antigravity actually uses the selected network path. The assurance model therefore separates three evidence layers:

1. **Process discovery** — inventory the live Antigravity process tree and surface unknown descendants.
2. **Route decision evidence** — query the authenticated loopback sing-box 1.14 connection tracker and observe the process path plus selected outbound (`vpn-direct` or an unexpected outbound).
3. **External egress evidence** — send a probe through `local-mixed -> vpn-direct` and ask an external observer which source IP it sees. Query the same observer without an HTTP proxy as a `system-direct` control path.

No single layer is sufficient by itself. The intended production invariant is:

```text
Antigravity process identity
        -> sing-box live connection
        -> outbound = vpn-direct
        -> vpn-direct bind_interface = selected VPN
        -> external observer sees VPN egress
```

The `system-direct` comparison is negative/control evidence. A different observed IP is strong evidence that the two policies have distinct external consequences. The same IP is **not** automatically a failure because a host-wide VPN can legitimately make both paths share one public NAT address.

## Current implementation

`internal/proxy/observability.go` exposes `RuntimeConnections` and `AttestAgentRoutes`. The connection tracker is available only on an authenticated loopback API service. The API secret is randomly generated, stored with owner-only permissions, never returned by the HTTP control plane and never logged.

`internal/proxy/egress.go` exposes `AttestPublicEgress`. Production probes currently use two independent observers:

- `https://api.ipify.org/`
- `https://www.cloudflare.com/cdn-cgi/trace`

The observers are queried concurrently through the managed local proxy. At least one valid IP response is required for external egress evidence to be `available`. If more than one valid VPN address is observed, all are retained because destination-dependent NAT/egress is legitimate and disagreement alone is not treated as failure.

After the first successful VPN-path observation, the same provider is queried with an HTTP transport whose `Proxy` is explicitly `nil`. This prevents inherited `HTTP_PROXY` / `HTTPS_PROXY` settings from contaminating the control path.

## Privacy contract

Public IP evidence is sensitive operational data. `AttestPublicEgress` returns it only to the local caller and does not persist or log the address. Diagnostic/support export must pass through the centralized redaction policy before this evidence is ever included in a bundle. This is part of R-019.

The probe sends no account identifiers, cookies, OAuth tokens, Antigravity payloads or user content. It performs only a small `GET` to a public source-address observer.

## Fail-closed behavior

The attestation is unavailable when:

- Agent Tunnel is not running;
- managed mixed-listener ownership is not proven;
- all configured observers fail;
- an observer returns a non-2xx response;
- an observer response does not contain a syntactically valid IPv4/IPv6 address.

Observer unavailability is evidence unavailability, not proof that the VPN route is wrong. Therefore this layer must not be silently converted into a routing failure. Higher-level orchestration may report `partial/degraded assurance` and retry with bounded backoff.

## Deterministic CI proof

The privileged Linux `netns` fixture has two independent L3 uplinks:

- `vpn0` source `10.250.0.2`;
- `sys0` source `10.251.0.2`.

A sink namespace hosts a source-address observer at `203.0.113.10`. The runtime test queries the exact same observer through `vpn-direct` and `system-direct` and asserts that the externally observed sources are `10.250.0.2` and `10.251.0.2` respectively. This proves that the selected outbound label has a real packet-path consequence, not merely a config or connection-tracker label.

The same CI job also proves TUN startup/cleanup, PID/path routing, crash recovery, reserved route/rule ownership and authenticated connection-tracker access.

## Remaining gap: per-PID correlation

The current sing-box CLI connection list exposes process path, source/destination and outbound, but the CLI formatter does not expose process PID. The live Antigravity inventory does have PIDs. Therefore complete `PID -> live socket -> sing-box connection -> vpn-direct -> external egress` correlation is not yet closed.

The next implementation step is to add source endpoint evidence to `RuntimeConnection` and correlate it with OS socket ownership:

- Linux: `/proc/<pid>/fd` socket inode -> `/proc/net/tcp{,6}` / UDP tables;
- Windows: exact local endpoint -> `netstat -ano`/native IP Helper ownership;
- ambiguous or unknown ownership must never be promoted to verified assurance.

Only after this correlation is runtime-tested on both supported platforms should the P1 item “every discovered helper PID is egress-attested” be marked complete or used as a hard `healthy` gate.
