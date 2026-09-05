package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const egressProbeBodyLimit = 4096

type EgressProbeEvidence struct {
	Provider   string `json:"provider"`
	Via        string `json:"via"`
	ObservedIP string `json:"observed_ip,omitempty"`
	Family     string `json:"family,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

type PublicEgressAttestation struct {
	Available            bool                  `json:"available"`
	ObservedAt           time.Time             `json:"observed_at"`
	VPNInterface         string                `json:"vpn_interface"`
	VPNObservedIPs       []string              `json:"vpn_observed_ips,omitempty"`
	SystemObservedIP     string                `json:"system_observed_ip,omitempty"`
	SystemRelation       string                `json:"system_relation"`
	VPNProviderSuccesses int                   `json:"vpn_provider_successes"`
	VPNProviderFailures  int                   `json:"vpn_provider_failures"`
	IPv4Observed         bool                  `json:"ipv4_observed"`
	IPv6Observed         bool                  `json:"ipv6_observed"`
	TCPObserved          bool                  `json:"tcp_observed"`
	UDPObserved          bool                  `json:"udp_observed"`
	QUICObserved         bool                  `json:"quic_observed"`
	CoverageComplete     bool                  `json:"coverage_complete"`
	Evidence             []EgressProbeEvidence `json:"evidence,omitempty"`
	Detail               string                `json:"detail"`
}

type egressProbeProvider struct {
	Name string
	URL  string
}

var defaultEgressProbeProviders = []egressProbeProvider{
	{Name: "ipify", URL: "https://api.ipify.org/"},
	{Name: "cloudflare-trace", URL: "https://www.cloudflare.com/cdn-cgi/trace"},
}

// AttestPublicEgress asks independent external observers which address they see
// when a request is sent through the managed local-mixed inbound. That inbound
// is hard-routed to vpn-direct, whose outbound is bound to the selected VPN
// interface. We then query the same observer without an HTTP proxy; while the
// Agent Tunnel is active that control request is handled by the TUN's final
// system-direct policy. The comparison is useful evidence but equality is not
// an error: a host-wide VPN can legitimately make both paths share one public
// address.
//
// No result is persisted or written to logs here. Public IPs are returned only
// to the local caller so support-bundle redaction policy remains centralized.
func (m *Manager) AttestPublicEgress(ctx context.Context) PublicEgressAttestation {
	return m.attestPublicEgressWithProviders(ctx, defaultEgressProbeProviders)
}

func (m *Manager) attestPublicEgressWithProviders(ctx context.Context, providers []egressProbeProvider) PublicEgressAttestation {
	r := PublicEgressAttestation{
		ObservedAt:     time.Now().UTC(),
		VPNInterface:   m.Config().VPNInterface,
		SystemRelation: "unknown",
	}
	if m.Mode() != ModeAgentTunnel || !m.ManagedRunning() {
		r.Detail = "Agent Tunnel is not running"
		return r
	}
	if owned, detail := m.ManagedListenerOwned(); !owned {
		r.Detail = "managed local proxy ownership is not proven: " + detail
		return r
	}
	if len(providers) == 0 {
		r.Detail = "no egress probe providers configured"
		return r
	}

	proxyURL, err := url.Parse(m.HTTPProxyURL())
	if err != nil {
		r.Detail = "parse managed proxy URL: " + err.Error()
		return r
	}
	vpnClient := egressHTTPClient(http.ProxyURL(proxyURL))
	vpnEvidence := probeEgressProviders(ctx, vpnClient, providers, "vpn-direct")
	r.Evidence = append(r.Evidence, vpnEvidence...)

	seen := map[string]bool{}
	var comparisonProvider *egressProbeProvider
	for i, e := range vpnEvidence {
		if e.OK {
			r.VPNProviderSuccesses++
			if e.Family == "ipv4" {
				r.IPv4Observed = true
			} else if e.Family == "ipv6" {
				r.IPv6Observed = true
			}
			// The current observers are HTTPS/TCP only. Keep this explicit and
			// fail closed until independent UDP and QUIC observers are wired.
			r.TCPObserved = true
			if !seen[e.ObservedIP] {
				seen[e.ObservedIP] = true
				r.VPNObservedIPs = append(r.VPNObservedIPs, e.ObservedIP)
			}
			if comparisonProvider == nil {
				p := providers[i]
				comparisonProvider = &p
			}
		} else {
			r.VPNProviderFailures++
		}
	}
	r.CoverageComplete = r.IPv4Observed && r.IPv6Observed && r.TCPObserved && r.UDPObserved && r.QUICObserved
	sort.Strings(r.VPNObservedIPs)
	if len(r.VPNObservedIPs) == 0 {
		r.Detail = fmt.Sprintf("external vpn-direct egress could not be observed through %d provider(s)", len(providers))
		return r
	}
	r.Available = true

	// Compare against the same provider that first succeeded through vpn-direct.
	// Proxy=nil is intentional: never inherit HTTP_PROXY/HTTPS_PROXY from the
	// desktop environment for the system-direct control path.
	if comparisonProvider != nil {
		systemClient := egressHTTPClient(nil)
		system := probeOneEgress(ctx, systemClient, *comparisonProvider, "system-direct")
		r.Evidence = append(r.Evidence, system)
		if system.OK {
			r.SystemObservedIP = system.ObservedIP
			for _, ip := range r.VPNObservedIPs {
				if ip == system.ObservedIP {
					r.SystemRelation = "same"
					break
				}
			}
			if r.SystemRelation == "unknown" {
				r.SystemRelation = "different"
			}
		}
	}

	switch {
	case len(r.VPNObservedIPs) > 1 && r.SystemObservedIP != "":
		r.Detail = fmt.Sprintf("vpn-direct externally observed via %s with %d valid egress addresses; system-direct comparison is %s", r.VPNInterface, len(r.VPNObservedIPs), r.SystemRelation)
	case len(r.VPNObservedIPs) > 1:
		r.Detail = fmt.Sprintf("vpn-direct externally observed via %s with %d valid egress addresses; system-direct comparison unavailable", r.VPNInterface, len(r.VPNObservedIPs))
	case r.SystemObservedIP != "":
		r.Detail = fmt.Sprintf("vpn-direct external egress observed via %s; system-direct comparison is %s", r.VPNInterface, r.SystemRelation)
	default:
		r.Detail = fmt.Sprintf("vpn-direct external egress observed via %s; system-direct comparison unavailable", r.VPNInterface)
	}
	return r
}

func egressHTTPClient(proxy func(*http.Request) (*url.URL, error)) *http.Client {
	tr := &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   4 * time.Second,
			KeepAlive: -1,
		}).DialContext,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func probeEgressProviders(ctx context.Context, client *http.Client, providers []egressProbeProvider, via string) []EgressProbeEvidence {
	type indexed struct {
		i int
		e EgressProbeEvidence
	}
	ch := make(chan indexed, len(providers))
	for i, p := range providers {
		go func(i int, p egressProbeProvider) {
			ch <- indexed{i: i, e: probeOneEgress(ctx, client, p, via)}
		}(i, p)
	}
	out := make([]EgressProbeEvidence, len(providers))
	for range providers {
		x := <-ch
		out[x.i] = x.e
	}
	return out
}

func probeOneEgress(ctx context.Context, client *http.Client, provider egressProbeProvider, via string) EgressProbeEvidence {
	start := time.Now()
	r := EgressProbeEvidence{Provider: provider.Name, Via: via}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.URL, nil)
	if err != nil {
		r.Error = err.Error()
		r.DurationMS = time.Since(start).Milliseconds()
		return r
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "AntigravitiProxi/egress-attestation")
	resp, err := client.Do(req)
	if err != nil {
		r.Error = err.Error()
		r.DurationMS = time.Since(start).Milliseconds()
		return r
	}
	defer resp.Body.Close()
	r.HTTPStatus = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		r.Error = resp.Status
		r.DurationMS = time.Since(start).Milliseconds()
		return r
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, egressProbeBodyLimit))
	if err != nil {
		r.Error = err.Error()
		r.DurationMS = time.Since(start).Milliseconds()
		return r
	}
	ip, err := parseObservedIP(string(body))
	if err != nil {
		r.Error = err.Error()
		r.DurationMS = time.Since(start).Milliseconds()
		return r
	}
	r.ObservedIP = ip.String()
	if ip.To4() != nil {
		r.Family = "ipv4"
	} else {
		r.Family = "ipv6"
	}
	r.OK = true
	r.DurationMS = time.Since(start).Milliseconds()
	return r
}

func parseObservedIP(body string) (net.IP, error) {
	trimmed := strings.TrimSpace(body)
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip, nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			if ip := net.ParseIP(strings.TrimSpace(strings.TrimPrefix(line, "ip="))); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, fmt.Errorf("provider response did not contain a valid IP address")
}
