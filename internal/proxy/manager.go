package proxy

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const DefaultSingBoxVersion = "1.13.1"

type Logger func(level, message string)
type Config struct { Root string; Host string; Port int; VPNInterface string; DNSProvider string; SingBoxVer string }
type Manager struct { mu sync.Mutex; cfg Config; cmd *exec.Cmd; logger Logger }
type release struct { Assets []struct { Name string `json:"name"`; BrowserDownloadURL string `json:"browser_download_url"`; Digest string `json:"digest"` } `json:"assets"` }

func New(cfg Config, logger Logger) *Manager { if cfg.Host==""{cfg.Host="127.0.0.1"};if cfg.Port==0{cfg.Port=7890};if cfg.DNSProvider==""{cfg.DNSProvider="cloudflare"};if cfg.SingBoxVer==""{cfg.SingBoxVer=DefaultSingBoxVersion};return &Manager{cfg:cfg,logger:logger} }
func (m *Manager) log(level,msg string){if m.logger!=nil{m.logger(level,msg)}}
func (m *Manager) SetVPNInterface(name string){m.mu.Lock();m.cfg.VPNInterface=name;m.mu.Unlock()}
func (m *Manager) SetDNSProvider(name string){m.mu.Lock();m.cfg.DNSProvider=name;m.mu.Unlock()}
func (m *Manager) Config() Config{m.mu.Lock();defer m.mu.Unlock();return m.cfg}
func (m *Manager) ConfigPath() string{return filepath.Join(m.cfg.Root,"sing-box.json")}
func (m *Manager) LogPath() string{return filepath.Join(m.cfg.Root,"sing-box.log")}
func (m *Manager) ErrPath() string{return filepath.Join(m.cfg.Root,"sing-box-error.log")}
func executableName()string{if runtime.GOOS=="windows"{return "sing-box.exe"};return "sing-box"}
func (m *Manager) ManagedPath()string{return filepath.Join(m.cfg.Root,"bin",executableName())}
func (m *Manager) Find()string{if p:=m.ManagedPath();fileExists(p){return p};if p,e:=exec.LookPath(executableName());e==nil{return p};if p,e:=exec.LookPath("sing-box");e==nil{return p};return ""}
func (m *Manager) Version(ctx context.Context)string{p:=m.Find();if p==""{return ""};out,e:=exec.CommandContext(ctx,p,"version").CombinedOutput();if e!=nil{return ""};first:=strings.TrimSpace(string(out));if i:=strings.IndexByte(first,'\n');i>=0{first=first[:i]};return first}

func (m *Manager) Install(ctx context.Context)(string,error){
	if p:=m.Find();p!=""{m.log("info","sing-box already available: "+p);return p,nil}
	if runtime.GOOS!="windows"&&runtime.GOOS!="linux"{return "",fmt.Errorf("unsupported OS: %s",runtime.GOOS)}
	if e:=os.MkdirAll(filepath.Join(m.cfg.Root,"bin"),0o755);e!=nil{return "",e}
	ver:=m.cfg.SingBoxVer;api:="https://api.github.com/repos/SagerNet/sing-box/releases/tags/v"+url.PathEscape(ver);m.log("info","fetching official sing-box release metadata v"+ver)
	req,_:=http.NewRequestWithContext(ctx,http.MethodGet,api,nil);req.Header.Set("Accept","application/vnd.github+json");resp,e:=(&http.Client{Timeout:30*time.Second}).Do(req);if e!=nil{return "",e};defer resp.Body.Close();if resp.StatusCode!=http.StatusOK{return "",fmt.Errorf("GitHub release API: %s",resp.Status)}
	var rel release;if e=json.NewDecoder(resp.Body).Decode(&rel);e!=nil{return "",e};want:=assetNameFor(runtime.GOOS,runtime.GOARCH,ver);var downloadURL,digest string;for _,a:=range rel.Assets{if a.Name==want{downloadURL,digest=a.BrowserDownloadURL,a.Digest;break}};if downloadURL==""{return "",fmt.Errorf("release asset not found: %s",want)}
	archive:=filepath.Join(m.cfg.Root,want);if e=downloadFile(ctx,downloadURL,archive,m.log);e!=nil{return "",e};defer os.Remove(archive)
	if digest!=""{got,e:=sha256File(archive);if e!=nil{return "",e};expected:=strings.TrimPrefix(strings.ToLower(digest),"sha256:");if !strings.EqualFold(got,expected){return "",fmt.Errorf("SHA-256 mismatch: expected %s got %s",expected,got)};m.log("info","SHA-256 verified against GitHub release metadata")}else{m.log("warn","release metadata has no digest; archive authenticity could not be pinned")}
	tmp:=filepath.Join(m.cfg.Root,"extract");_ = os.RemoveAll(tmp);if e=os.MkdirAll(tmp,0o755);e!=nil{return "",e};defer os.RemoveAll(tmp);if strings.HasSuffix(want,".zip"){e=extractZip(archive,tmp)}else{e=extractTarGz(archive,tmp)};if e!=nil{return "",e};found,e:=findFile(tmp,executableName());if e!=nil{return "",e};dest:=m.ManagedPath();if e=copyFile(found,dest,0o755);e!=nil{return "",e};m.log("info","installed managed sing-box: "+dest);return dest,nil
}
func assetNameFor(goos,goarch,ver string)string{if goos=="windows"{return fmt.Sprintf("sing-box-%s-windows-%s.zip",ver,goarch)};return fmt.Sprintf("sing-box-%s-linux-%s.tar.gz",ver,goarch)}

func (m *Manager) WriteConfig()error{m.mu.Lock();cfg:=m.cfg;m.mu.Unlock();return writeConfig(cfg,m.ConfigPath())}
func writeConfig(cfg Config,path string)error{if e:=os.MkdirAll(cfg.Root,0o755);e!=nil{return e};dnsIP,dnsName:="1.1.1.1","cloudflare-dns.com";if strings.EqualFold(cfg.DNSProvider,"google"){dnsIP,dnsName="8.8.8.8","dns.google"};dnsServer:=map[string]any{"type":"https","tag":"secure-doh","server":dnsIP,"server_port":443,"path":"/dns-query","tls":map[string]any{"enabled":true,"server_name":dnsName}};direct:=map[string]any{"type":"direct","tag":"vpn-direct","domain_resolver":map[string]any{"server":"secure-doh","strategy":"ipv4_only"}};if cfg.VPNInterface!=""{dnsServer["bind_interface"]=cfg.VPNInterface;direct["bind_interface"]=cfg.VPNInterface};doc:=map[string]any{"log":map[string]any{"level":"info","timestamp":true},"dns":map[string]any{"servers":[]any{dnsServer},"final":"secure-doh","strategy":"ipv4_only"},"inbounds":[]any{map[string]any{"type":"mixed","tag":"local-mixed","listen":cfg.Host,"listen_port":cfg.Port}},"outbounds":[]any{direct},"route":map[string]any{"default_domain_resolver":map[string]any{"server":"secure-doh","strategy":"ipv4_only"},"final":"vpn-direct"}};b,e:=json.MarshalIndent(doc,"","  ");if e!=nil{return e};return os.WriteFile(path,append(b,'\n'),0o600)}
func (m *Manager) writeConfigLocked()error{return writeConfig(m.cfg,m.ConfigPath())}
func (m *Manager) Start(ctx context.Context)error{m.mu.Lock();defer m.mu.Unlock();if m.cmd!=nil&&m.cmd.Process!=nil{return errors.New("proxy already started by this process")};p:=m.Find();if p==""{return errors.New("sing-box not installed")};if e:=m.writeConfigLocked();e!=nil{return e};check:=exec.CommandContext(ctx,p,"check","-c",m.ConfigPath());if out,e:=check.CombinedOutput();e!=nil{return fmt.Errorf("sing-box config check failed: %v: %s",e,strings.TrimSpace(string(out)))};logf,e:=os.OpenFile(m.LogPath(),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0o600);if e!=nil{return e};errf,e:=os.OpenFile(m.ErrPath(),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0o600);if e!=nil{_ = logf.Close();return e};cmd:=exec.Command(p,"run","-c",m.ConfigPath());cmd.Stdout,cmd.Stderr=logf,errf;if e=cmd.Start();e!=nil{_ = logf.Close();_ = errf.Close();return e};m.cmd=cmd;go func(){e:=cmd.Wait();_ = logf.Close();_ = errf.Close();m.mu.Lock();if m.cmd==cmd{m.cmd=nil};m.mu.Unlock();if e!=nil{m.log("error","sing-box exited: "+e.Error())}else{m.log("info","sing-box stopped")}}();m.log("info",fmt.Sprintf("local mixed proxy started at %s:%d",m.cfg.Host,m.cfg.Port));return nil}
func (m *Manager) Stop()error{m.mu.Lock();cmd:=m.cmd;m.mu.Unlock();if cmd==nil||cmd.Process==nil{return nil};return cmd.Process.Kill()}
func (m *Manager) Running()bool{cfg:=m.Config();c,e:=net.DialTimeout("tcp",net.JoinHostPort(cfg.Host,fmt.Sprint(cfg.Port)),350*time.Millisecond);if e!=nil{return false};_ = c.Close();return true}
func (m *Manager) HTTPProxyURL()string{cfg:=m.Config();return fmt.Sprintf("http://%s:%d",cfg.Host,cfg.Port)}
func (m *Manager) SOCKSProxyAddr()string{cfg:=m.Config();return net.JoinHostPort(cfg.Host,fmt.Sprint(cfg.Port))}

func downloadFile(ctx context.Context,u,path string,logger Logger)error{req,_:=http.NewRequestWithContext(ctx,http.MethodGet,u,nil);resp,e:=(&http.Client{Timeout:3*time.Minute}).Do(req);if e!=nil{return e};defer resp.Body.Close();if resp.StatusCode!=http.StatusOK{return fmt.Errorf("download: %s",resp.Status)};f,e:=os.Create(path);if e!=nil{return e};defer f.Close();if logger!=nil{logger("info","downloading "+u)};_,e=io.Copy(f,resp.Body);return e}
func sha256File(path string)(string,error){f,e:=os.Open(path);if e!=nil{return "",e};defer f.Close();h:=sha256.New();if _,e=io.Copy(h,f);e!=nil{return "",e};return hex.EncodeToString(h.Sum(nil)),nil}
func fileExists(p string)bool{st,e:=os.Stat(p);return e==nil&&!st.IsDir()}
func copyFile(src,dst string,mode os.FileMode)error{in,e:=os.Open(src);if e!=nil{return e};defer in.Close();if e=os.MkdirAll(filepath.Dir(dst),0o755);e!=nil{return e};out,e:=os.OpenFile(dst,os.O_CREATE|os.O_TRUNC|os.O_WRONLY,mode);if e!=nil{return e};if _,e=io.Copy(out,in);e!=nil{_ = out.Close();return e};return out.Close()}
func findFile(root,name string)(string,error){var found string;err:=filepath.Walk(root,func(p string,info os.FileInfo,e error)error{if e!=nil{return e};if !info.IsDir()&&info.Name()==name{found=p;return filepath.SkipDir};return nil});if err!=nil{return "",err};if found==""{return "",fmt.Errorf("%s not found in archive",name)};return found,nil}
func extractZip(src,dst string)error{r,e:=zip.OpenReader(src);if e!=nil{return e};defer r.Close();for _,f:=range r.File{p:=filepath.Join(dst,filepath.Clean(f.Name));if !strings.HasPrefix(p,filepath.Clean(dst)+string(os.PathSeparator)){return errors.New("zip path traversal")};if f.FileInfo().IsDir(){if e=os.MkdirAll(p,0o755);e!=nil{return e};continue};if e=os.MkdirAll(filepath.Dir(p),0o755);e!=nil{return e};rc,e:=f.Open();if e!=nil{return e};out,e:=os.OpenFile(p,os.O_CREATE|os.O_TRUNC|os.O_WRONLY,f.Mode());if e!=nil{rc.Close();return e};_,e=io.Copy(out,rc);rc.Close();out.Close();if e!=nil{return e}};return nil}
func extractTarGz(src,dst string)error{f,e:=os.Open(src);if e!=nil{return e};defer f.Close();gz,e:=gzip.NewReader(f);if e!=nil{return e};defer gz.Close();tr:=tar.NewReader(gz);for{h,e:=tr.Next();if e==io.EOF{break};if e!=nil{return e};p:=filepath.Join(dst,filepath.Clean(h.Name));if !strings.HasPrefix(p,filepath.Clean(dst)+string(os.PathSeparator)){return errors.New("tar path traversal")};switch h.Typeflag{case tar.TypeDir:if e=os.MkdirAll(p,0o755);e!=nil{return e};case tar.TypeReg:if e=os.MkdirAll(filepath.Dir(p),0o755);e!=nil{return e};out,e:=os.OpenFile(p,os.O_CREATE|os.O_TRUNC|os.O_WRONLY,os.FileMode(h.Mode));if e!=nil{return e};_,e=io.Copy(out,tr);out.Close();if e!=nil{return e}}};return nil}
