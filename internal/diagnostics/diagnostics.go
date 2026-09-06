package diagnostics

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/platform"
)

type DNSComparison struct {
	Domain         string   `json:"domain"`
	System         []string `json:"system"`
	Cloudflare     []string `json:"cloudflare"`
	Google         []string `json:"google"`
	SystemAAAA     []string `json:"system_aaaa,omitempty"`
	CloudflareAAAA []string `json:"cloudflare_aaaa,omitempty"`
	GoogleAAAA     []string `json:"google_aaaa,omitempty"`
	Suspicious     bool     `json:"suspicious"`
}
type Snapshot struct {
	Time       time.Time            `json:"time"`
	Interfaces []platform.Interface `json:"interfaces"`
	DNS        []DNSComparison      `json:"dns"`
	PublicIP   string               `json:"public_ip,omitempty"`
	PublicGeo  string               `json:"public_geo,omitempty"`
}

func Collect(ctx context.Context, domains []string) (Snapshot, error) {
	ifaces, e := platform.Interfaces()
	if e != nil {
		return Snapshot{}, e
	}
	out := Snapshot{Time: time.Now(), Interfaces: ifaces}

	var (
		pubIP  string
		pubGeo string
		geoWg  sync.WaitGroup
	)
	geoWg.Add(1)
	go func() {
		defer geoWg.Done()
		pubIP, pubGeo = publicGeo(ctx)
	}()

	dnsResults := make([]DNSComparison, len(domains))
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			var (
				sys, cf, gg, sysAAAA, cfAAAA, ggAAAA []string
				dwg                                  sync.WaitGroup
			)
			dwg.Add(6)
			go func() { defer dwg.Done(); sys = systemA(ctx, domain) }()
			go func() { defer dwg.Done(); cf = dohA(ctx, "cloudflare-dns.com", "1.1.1.1:443", domain) }()
			go func() { defer dwg.Done(); gg = dohA(ctx, "dns.google", "8.8.8.8:443", domain) }()
			go func() { defer dwg.Done(); sysAAAA = systemAAAA(ctx, domain) }()
			go func() { defer dwg.Done(); cfAAAA = dohAAAA(ctx, "cloudflare-dns.com", "1.1.1.1:443", domain) }()
			go func() { defer dwg.Done(); ggAAAA = dohAAAA(ctx, "dns.google", "8.8.8.8:443", domain) }()
			dwg.Wait()

			trusted := union(cf, gg)
			trustedAAAA := union(cfAAAA, ggAAAA)
			suspicious := (len(sys) > 0 && len(trusted) == 0) || (len(sys) == 0 && len(trusted) > 0) ||
				(len(sysAAAA) > 0 && len(trustedAAAA) == 0) || (len(sysAAAA) == 0 && len(trustedAAAA) > 0)
			dnsResults[idx] = DNSComparison{
				Domain:         domain,
				System:         sys,
				Cloudflare:     cf,
				Google:         gg,
				SystemAAAA:     sysAAAA,
				CloudflareAAAA: cfAAAA,
				GoogleAAAA:     ggAAAA,
				Suspicious:     suspicious,
			}
		}(i, d)
	}
	wg.Wait()
	geoWg.Wait()

	out.DNS = dnsResults
	if pubIP != "" {
		out.PublicIP, out.PublicGeo = pubIP, pubGeo
	}
	return out, nil
}
func systemA(ctx context.Context, domain string) []string {
	return lookupIP(ctx, "ip4", domain)
}

func systemAAAA(ctx context.Context, domain string) []string {
	return lookupIP(ctx, "ip6", domain)
}

func lookupIP(ctx context.Context, network, domain string) []string {
	ips, e := net.DefaultResolver.LookupIP(ctx, network, domain)
	if e != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return dedupe(out)
}

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func dohA(ctx context.Context, host, pinnedAddr, domain string) []string {
	return dohType(ctx, host, pinnedAddr, domain, "A", 1)
}

func dohAAAA(ctx context.Context, host, pinnedAddr, domain string) []string {
	return dohType(ctx, host, pinnedAddr, domain, "AAAA", 28)
}

func dohType(ctx context.Context, host, pinnedAddr, domain, queryType string, answerType int) []string {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", pinnedAddr)
	}, TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
	c := &http.Client{Timeout: 15 * time.Second, Transport: tr}
	u := "https://" + host + "/dns-query?name=" + url.QueryEscape(domain) + "&type=" + queryType
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, e := c.Do(req)
	if e != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var dr dohResponse
	if json.NewDecoder(resp.Body).Decode(&dr) != nil {
		return nil
	}
	out := []string{}
	for _, a := range dr.Answer {
		if a.Type == answerType && net.ParseIP(a.Data) != nil {
			out = append(out, a.Data)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}
func publicGeo(ctx context.Context) (string, string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json", nil)
	resp, e := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if e != nil {
		return "", ""
	}
	defer resp.Body.Close()
	var v struct{ IP, Country, Region, City, Org string }
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return "", ""
	}
	parts := []string{}
	for _, p := range []string{v.Country, v.Region, v.City, v.Org} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	return v.IP, strings.Join(parts, " / ")
}
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := []string{in[0]}
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
func union(a, b []string) []string {
	m := map[string]bool{}
	for _, v := range a {
		m[v] = true
	}
	for _, v := range b {
		m[v] = true
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func intersects(a, b []string) bool {
	m := map[string]bool{}
	for _, v := range b {
		m[v] = true
	}
	for _, v := range a {
		if m[v] {
			return true
		}
	}
	return false
}
func FormatText(s Snapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AntigravitiProxi diagnostics\nTime: %s\nPublic IP: %s\nGeo: %s\n\n", s.Time.Format(time.RFC3339), Redact(s.PublicIP), Redact(s.PublicGeo))
	b.WriteString("Interfaces:\n")
	for _, it := range s.Interfaces {
		fmt.Fprintf(&b, "- %s vpn=%v flags=%v addrs=%v\n", Redact(it.Name), it.LikelyVPN, it.Flags, Redact(fmt.Sprint(it.Addresses)))
	}
	b.WriteString("\nDNS:\n")
	for _, d := range s.DNS {
		fmt.Fprintf(&b, "- %s\n  system=%s\n  cloudflare=%s\n  google=%s\n  system_aaaa=%s\n  cloudflare_aaaa=%s\n  google_aaaa=%s\n  suspicious=%v\n", Redact(d.Domain), Redact(fmt.Sprint(d.System)), Redact(fmt.Sprint(d.Cloudflare)), Redact(fmt.Sprint(d.Google)), Redact(fmt.Sprint(d.SystemAAAA)), Redact(fmt.Sprint(d.CloudflareAAAA)), Redact(fmt.Sprint(d.GoogleAAAA)), d.Suspicious)
	}
	return b.String()
}
func TrustedA(ctx context.Context, domain string) []string {
	if out := dohA(ctx, "cloudflare-dns.com", "1.1.1.1:443", domain); len(out) > 0 {
		return out
	}
	return dohA(ctx, "dns.google", "8.8.8.8:443", domain)
}
