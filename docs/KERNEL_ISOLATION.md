# Linux Kernel Isolation Contract

Agent Tunnel has two deliberately different Linux modes:

* `userspace-soft` — the existing sing-box TUN with process/path routing;
* `kernel-hard` — Antigravity is launched in a dedicated cgroup and network
  namespace, with policy routing and an nftables kill-switch owned by the
  privileged helper.

The soft mode must never be presented as proof that an arbitrary Antigravity
descendant cannot escape. Process names and paths are sing-box routing
selectors. They are useful evidence, but they are not a kernel security
boundary.

## Hard-mode invariants

The hard backend may report `healthy` only when all of these are true:

1. Antigravity and its descendants are in the owned cgroup v2 subtree.
2. Their network namespace is owned by the current operation.
3. The namespace has no usable default path except the host veth.
4. Host policy routing sends traffic arriving from that veth to the selected
   VPN interface.
5. nftables drops cgroup traffic whose output interface is not the selected
   VPN, except for the explicitly discovered VPN transport endpoint routes.
6. IPv4 and IPv6 have equivalent policy. If IPv6 cannot be enforced, hard
   mode is blocked rather than silently degrading to IPv4-only protection.
7. Stopping the selected VPN makes Antigravity network operations fail closed.
8. Stopping Antigravity removes only the operation's namespace, veth, rules,
   route tables and nftables table.

`system-direct` is not a valid fallback in hard mode. If the selected VPN is
down or its route is unavailable, the application must be blocked.

## Launch boundary

The process must be stopped before it can create a socket, attached to the
owned cgroup, and resumed only after the kernel policy is committed. A normal
post-start PID scan is insufficient because it leaves a race before cgroup
attachment. The launcher therefore needs a fixed-function privileged helper
for namespace setup and cleanup; it must not accept arbitrary shell commands.

## Required diagnostics

The UI and API expose the enforcement level and evidence separately:

```text
enforcement: kernel-hard | userspace-soft | inactive
namespace:   name and inode
cgroup:      path and inode
policy:      IPv4 / IPv6 route and nftables status
kill_switch: pass / fail
vpn_down:    blocked / leak
cleanup:     clean / recovery-required
```

Unknown descendants are a warning in soft mode and expected evidence in hard
mode: their process name is irrelevant because they inherit the namespace and
cgroup policy.

## Verification matrix

Hard mode requires runtime tests for direct IPv4, direct IPv6, DNS, UDP, LAN
destinations, a renamed helper, a bundled helper, and an ordinary process in
the host namespace. The VPN-down test is mandatory. A failed test leaves the
mode degraded and blocks the protected process instead of selecting the host
default route.
