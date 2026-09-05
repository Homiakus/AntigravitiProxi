# Linux privilege bootstrap for Agent Tunnel

## Goal

Agent Tunnel needs TUN route control and process/socket attribution, but the AntigravitiProxi web control plane and Antigravity IDE should continue to run as the desktop user.

The Linux bootstrap therefore grants privileges only to the managed, hash-verified sing-box binary and uses the operating system authentication broker instead of collecting a password inside AntigravitiProxi.

## One-click startup sequence

When the user explicitly starts Agent Tunnel, the runtime performs the following sequence:

1. Verify/install the pinned managed sing-box binary.
2. Check `/dev/net/tun`.
3. If TUN is unavailable, invoke `modprobe tun` through PolicyKit (`pkexec`) or a terminal-attached `sudo` fallback.
4. Locate `getcap` and `setcap`.
5. If capability tooling is missing, install only the corresponding libcap package using the detected supported package manager.
6. Read current file capabilities from the managed sing-box binary.
7. If necessary, grant exactly:

   `cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep`

8. Re-read capabilities and fail closed if any required capability is still missing.
9. Continue with Agent Tunnel preflight, transactional startup, TUN/listener/VPN health evidence and runtime attestation.

## Authentication model

Preferred desktop path:

`AntigravitiProxi (user) -> pkexec -> distro PolicyKit dialog -> one narrow privileged command`

Fallback when the program was launched from an interactive terminal:

`AntigravitiProxi (user) -> sudo in existing terminal -> one narrow privileged command`

AntigravitiProxi never reads, stores, logs or forwards the user's administrator password.

## Why these capabilities are required

- `CAP_NET_ADMIN`: create/configure TUN and routing state.
- `CAP_NET_RAW`: networking operations required by the transparent data plane.
- `CAP_SYS_PTRACE`: inspect process ownership for socket attribution.
- `CAP_DAC_READ_SEARCH`: read kernel/process metadata needed to map sockets back to local processes.

Process attribution is part of the isolation invariant. A TUN that cannot prove which local process owns a connection must not be considered equivalent to process-aware routing.

## Security boundary

The managed binary is verified before privileged startup through the existing pinned-version, release-digest and installed-binary provenance checks. File capabilities are rechecked every Agent Tunnel start because package updates, binary replacement and file writes can remove them.

This bootstrap mitigates R-006 by avoiding the need to run the whole control plane as root. It does **not** close R-006 completely: the long-term architecture still calls for a minimal structured privileged helper that owns only a very small set of TUN lifecycle operations.

## Failure policy

Privilege preparation is fail-closed. If PolicyKit is unavailable, authorization is denied, the package manager fails, TUN cannot be loaded, or the post-`setcap` verification is incomplete, Agent Tunnel is not started and the UI displays the concrete remediation.
