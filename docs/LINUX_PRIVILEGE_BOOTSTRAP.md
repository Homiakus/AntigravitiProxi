# Linux privilege bootstrap for Agent Tunnel

## Goal

Agent Tunnel needs TUN route control and process/socket attribution, but the AntigravitiProxi web control plane and Antigravity IDE should continue to run as the desktop user.

The Linux bootstrap therefore grants privileges only to the managed, hash-verified sing-box binary and uses the operating system authentication broker instead of collecting a password inside AntigravitiProxi.

## One-click startup sequence

When the user explicitly starts Agent Tunnel, the ordinary-user control plane performs a readiness check. If TUN and file capabilities are already valid, no elevation occurs. Otherwise it computes the SHA-256 of the already verified managed sing-box and asks the OS to execute the same AntigravitiProxi binary in a fixed-function internal setup mode.

The privileged helper accepts only two inputs: the managed sing-box path and the expected SHA-256. It refuses an unexpected path, re-hashes the binary after elevation, and only then performs the fixed preparation sequence:

1. ensure `/dev/net/tun` exists, loading `tun` with `modprobe` when required;
2. locate `getcap` and `setcap`;
3. if capability tooling is missing, install only the corresponding libcap package using a supported package manager;
4. grant exactly `cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep` to the managed sing-box;
5. re-read capabilities and fail closed if any required capability is missing;
6. return to the ordinary-user control plane, which independently rechecks TUN/capability readiness before continuing with Agent Tunnel preflight and transactional startup.

This design normally produces **one PolicyKit authorization flow**, rather than a separate prompt for `modprobe`, package installation and `setcap`.

## Authentication model

Preferred desktop path:

`AntigravitiProxi (user) -> pkexec -> distro PolicyKit dialog -> fixed-function internal helper -> return to user process`

Fallback when the program was launched from an interactive terminal:

`AntigravitiProxi (user) -> sudo in existing terminal -> fixed-function internal helper -> return to user process`

AntigravitiProxi never reads, stores, logs or forwards the user's administrator password. It does not use `sudo -S`, stdin password piping or an application-owned askpass mechanism.

## Why these capabilities are required

- `CAP_NET_ADMIN`: create/configure TUN and routing state.
- `CAP_NET_RAW`: networking operations required by the transparent data plane.
- `CAP_SYS_PTRACE`: inspect process ownership for socket attribution.
- `CAP_DAC_READ_SEARCH`: read kernel/process metadata needed to map sockets back to local processes.

Process attribution is part of the isolation invariant. A TUN that cannot prove which local process owns a connection must not be considered equivalent to process-aware routing.

## Security boundary

The managed binary is verified before privileged startup through the pinned-version, release-digest and installed-binary provenance checks. The privileged helper then rechecks the exact SHA-256 after elevation, closing the time-of-check/time-of-use gap between ordinary-user verification and privileged `setcap`.

The helper is fixed-function: it cannot execute an arbitrary command supplied by the web UI. File capabilities are rechecked every Agent Tunnel start because package updates, binary replacement and file writes can remove them.

This bootstrap materially mitigates R-006 by avoiding elevation of the whole control plane. It does **not** close R-006 completely: the long-term architecture still calls for a smaller independently installed structured helper/service that can further reduce the lifetime of broad capabilities.

## Failure policy

Privilege preparation is fail-closed. If PolicyKit is unavailable, authorization is denied, the package manager fails, the binary hash changes, TUN cannot be loaded, or post-`setcap` verification is incomplete, Agent Tunnel is not started and the UI displays the concrete remediation.
