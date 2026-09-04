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
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/platform"
)

type DNSComparison struct { Domain string `json:"domain"`; System []string `json:"system"`; Cloudflare []string `json:"cloudflare"`; Google []string `json:"google"`; Suspicious bool `json:"suspicious"` }
type Snapshot struct { Time time.Time `json:"time"`; Interfaces []platform.Interface `json:"interfaces"`; DNS []DNSComparison `json:"dns"`; PublicIP string `json:"public_ip,omitempty"`; PublicGeo string `json:"public_geo,omitempty"` }

func Collect(ctx context.Context,domains []string)(Snapshot,error){ifaces,e:=platform.Interfaces();if e!=nil{return Snapshot{},e};out:=Snapshot{Time:time.Now(),Interfaces:ifaces};for _,d:=range domains{sys:=systemA(ctx,d);cf:=dohA(ctx,"cloudflare-dns.com","1.1.1.1:443",d);gg:=dohA(ctx,"dns.google","8.8.8.8:443",d);trusted:=union(cf,gg);out.DNS=append(out.DNS,DNSComparison{Domain:d,System:sys,Cloudflare:cf,Google:gg,Suspicious:len(sys)>0&&len(trusted)>0&&!intersects(sys,trusted)})};if ip,geo:=publicGeo(ctx);ip!=""{out.PublicIP,out.PublicGeo=ip,geo};return out,nil}
func systemA(ctx context.Context,domain string)[]string{ips,e:=net.DefaultResolver.LookupIP(ctx,"ip4",domain);if e!=nil{return nil};out:=make([]string,0,len(ips));for _,ip:=range ips{out=append(out,ip.String())};sort.Strings(out);return dedupe(out)}
type dohResponse struct{Answer []struct{Type int `json:"type"`;Data string `json:"data"`} `json:"Answer"`}
func dohA(ctx context.Context,host,pinnedAddr,domain string)[]string{dialer:=&net.Dialer{Timeout:10*time.Second};tr:=&http.Transport{DialContext:func(ctx context.Context,network,address string)(net.Conn,error){return dialer.DialContext(ctx,"tcp",pinnedAddr)},TLSClientConfig:&tls.Config{ServerName:host,MinVersion:tls.VersionTLS12}};c:=&http.Client{Timeout:15*time.Second,Transport:tr};u:="https://"+host+"/dns-query?name="+url.QueryEscape(domain)+"&type=A";req,_:=http.NewRequestWithContext(ctx,http.MethodGet,u,nil);req.Header.Set("Accept","application/dns-json");resp,e:=c.Do(req);if e!=nil{return nil};defer resp.Body.Close();if resp.StatusCode!=http.StatusOK{return nil};var dr dohResponse;if json.NewDecoder(resp.Body).Decode(&dr)!=nil{return nil};out:=[]string{};for _,a:=range dr.Answer{if a.Type==1&&net.ParseIP(a.Data)!=nil{out=append(out,a.Data)}};sort.Strings(out);return dedupe(out)}
func publicGeo(ctx context.Context)(string,string){req,_:=http.NewRequestWithContext(ctx,http.MethodGet,"https://ipinfo.io/json",nil);resp,e:=(&http.Client{Timeout:10*time.Second}).Do(req);if e!=nil{return "",""};defer resp.Body.Close();var v struct{IP,Country,Region,City,Org string};if json.NewDecoder(resp.Body).Decode(&v)!=nil{return "",""};parts:=[]string{};for _,p:=range []string{v.Country,v.Region,v.City,v.Org}{if strings.TrimSpace(p)!=""{parts=append(parts,p)}};return v.IP,strings.Join(parts," / ")}
func dedupe(in []string)[]string{if len(in)==0{return nil};out:=[]string{in[0]};for _,v:=range in[1:]{if v!=out[len(out)-1]{out=append(out,v)}};return out}
func union(a,b []string)[]string{m:=map[string]bool{};for _,v:=range a{m[v]=true};for _,v:=range b{m[v]=true};out:=make([]string,0,len(m));for v:=range m{out=append(out,v)};sort.Strings(out);return out}
func intersects(a,b []string)bool{m:=map[string]bool{};for _,v:=range b{m[v]=true};for _,v:=range a{if m[v]{return true}};return false}
func FormatText(s Snapshot)string{var b strings.Builder;fmt.Fprintf(&b,"AntigravitiProxi diagnostics\nTime: %s\nPublic IP: %s\nGeo: %s\n\n",s.Time.Format(time.RFC3339),s.PublicIP,s.PublicGeo);b.WriteString("Interfaces:\n");for _,it:=range s.Interfaces{fmt.Fprintf(&b,"- %s vpn=%v flags=%v addrs=%v\n",it.Name,it.LikelyVPN,it.Flags,it.Addresses)};b.WriteString("\nDNS:\n");for _,d:=range s.DNS{fmt.Fprintf(&b,"- %s\n  system=%v\n  cloudflare=%v\n  google=%v\n  suspicious=%v\n",d.Domain,d.System,d.Cloudflare,d.Google,d.Suspicious)};return b.String()}
func TrustedA(ctx context.Context,domain string)[]string{if out:=dohA(ctx,"cloudflare-dns.com","1.1.1.1:443",domain);len(out)>0{return out};return dohA(ctx,"dns.google","8.8.8.8:443",domain)}
