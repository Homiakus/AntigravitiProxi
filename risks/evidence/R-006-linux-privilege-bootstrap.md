# R-006 evidence — Linux automatic privilege bootstrap

Status: partial mitigation, risk remains `mitigating`.

Implemented evidence:

- desktop control plane remains an ordinary user process;
- Antigravity IDE remains an ordinary user process;
- managed sing-box is verified before privileged startup;
- `/dev/net/tun` is checked and `modprobe tun` is requested through the OS privilege broker only when required;
- capability tooling is discovered and can be installed automatically for supported distributions;
- only the managed sing-box binary receives `cap_net_admin,cap_net_raw,cap_sys_ptrace,cap_dac_read_search+ep`;
- post-authorization `getcap` verification is fail-closed;
- passwords are never read or stored by AntigravitiProxi;
- PolicyKit/pkexec is preferred; terminal-attached sudo is only a fallback;
- Linux capability parsing has unit tests;
- existing privileged Linux TUN/netns integration tests remain the runtime evidence gate.

Residual risk:

This is not yet the final minimal privileged-helper architecture described by R-006. The managed sing-box process itself still holds broad Linux capabilities for its lifetime. The target architecture remains a narrowly scoped structured helper that owns only authenticated TUN lifecycle operations and can further reduce the long-lived privileged surface.
