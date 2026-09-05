package antigravity

import (
	"testing"
	"time"
)

func TestHostsOverrideOwnershipRequiresExactIPAndDomain(t *testing.T) {
	metadata := hostsOverrideMetadata{IP: "192.0.2.7", Domain: "daily-cloudcode-pa.googleapis.com", ExpiresAt: time.Now()}
	if hasOwnedHostsLine(hostsStart+"\n192.0.2.8    "+metadata.Domain+"\n"+hostsEnd, metadata) {
		t.Fatal("ownership unexpectedly proven for a different IP")
	}
	if !hasOwnedHostsLine(hostsStart+"\n"+metadata.IP+"    "+metadata.Domain+"\n"+hostsEnd, metadata) {
		t.Fatal("exact owned hosts line was not recognized")
	}
}
