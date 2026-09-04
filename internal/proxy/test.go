package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type TestResult struct { Name string `json:"name"`; URL string `json:"url"`; Via string `json:"via"`; HTTPStatus int `json:"http_status,omitempty"`; OK bool `json:"ok"`; Error string `json:"error,omitempty"`; DurationMS int64 `json:"duration_ms"` }
var Targets=[]string{"https://oauth2.googleapis.com/","https://cloudcode-pa.googleapis.com/","https://daily-cloudcode-pa.googleapis.com/","https://antigravity.google/"}
func (m *Manager) Tests(ctx context.Context) []TestResult { results:=make([]TestResult,0,len(Targets)+2);purl,_:=url.Parse(m.HTTPProxyURL());tr:=&http.Transport{Proxy:http.ProxyURL(purl),TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12}};client:=&http.Client{Timeout:20*time.Second,Transport:tr,CheckRedirect:func(req *http.Request,via []*http.Request)error{return http.ErrUseLastResponse}};for _,target:=range Targets{results=append(results,runHTTPTest(ctx,client,target,"http-proxy"))};str:=&http.Transport{DialContext:SOCKS5DialContext(m.SOCKSProxyAddr(),15*time.Second),TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12}};sc:=&http.Client{Timeout:20*time.Second,Transport:str,CheckRedirect:func(req *http.Request,via []*http.Request)error{return http.ErrUseLastResponse}};results=append(results,runHTTPTest(ctx,sc,"https://daily-cloudcode-pa.googleapis.com/","socks5h"));results=append(results,runHTTPTest(ctx,client,"https://api.ipify.org/","http-proxy"));return results }
func runHTTPTest(ctx context.Context,client *http.Client,target,via string)TestResult{start:=time.Now();r:=TestResult{Name:target,URL:target,Via:via};req,_:=http.NewRequestWithContext(ctx,http.MethodHead,target,nil);resp,err:=client.Do(req);if err!=nil&&target=="https://api.ipify.org/"{req,_=http.NewRequestWithContext(ctx,http.MethodGet,target,nil);resp,err=client.Do(req)};r.DurationMS=time.Since(start).Milliseconds();if err!=nil{r.Error=err.Error();return r};defer resp.Body.Close();r.HTTPStatus=resp.StatusCode;r.OK=true;return r}
func (r TestResult) String()string{if r.OK{return fmt.Sprintf("%s via %s -> HTTP %d (%d ms)",r.URL,r.Via,r.HTTPStatus,r.DurationMS)};return fmt.Sprintf("%s via %s -> %s",r.URL,r.Via,r.Error)}
