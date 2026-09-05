//go:build !linux

package proxy

func platformProcessIdentity(pid int) (string, error) {
	_ = pid
	// Windows and other platforms currently have no native creation-time
	// adapter in this package. An empty value is deliberate: journal recovery
	// treats a live PID without identity as unsafe and fails closed.
	return "", nil
}
