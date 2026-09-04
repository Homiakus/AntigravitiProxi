package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/antigravity"
	"github.com/Homiakus/AntigravitiProxi/internal/diagnostics"
	"github.com/Homiakus/AntigravitiProxi/internal/platform"
	"github.com/Homiakus/AntigravitiProxi/internal/proxy"
	"github.com/Homiakus/AntigravitiProxi/internal/webui"
)

var targetDomains=[]string{"antigravity.google","oauth2.googleapis.com","cloudcode-pa.googleapis.com","daily-cloudcode-pa.googleapis.com"}
type Server struct{mu sync.Mutex;root string;settingsPath string;settings Settings;pm *proxy.Manager;events *eventHub;csrf string}
type Status struct{OS string `json:"os"`;Arch string `json:"arch"`;ProxyRunning bool `json:"proxy_running"`;ProxyURL string `json:"proxy_url"`;SOCKSURL string `json:"socks_url"`;SingBoxPath string `json:"sing_box_path,omitempty"`;SingBoxVersion string `json:"sing_box_version,omitempty"`;AntigravityPath string `json:"antigravity_path,omitempty"`;Settings Settings `json:"settings"`;Interfaces []platform.Interface `json:"interfaces"`}
func New()(*Server,error){root,e:=platform.ConfigDir();if e!=nil{return nil,e};if e=os.MkdirAll(root,0o755);e!=nil{return nil,e};settingsPath:=filepath.Join(root,"config.json");settings:=loadSettings(settingsPath);ifaces,_:=platform.Interfaces();if settings.VPNInterface==""{for _,it:=range ifaces{if it.LikelyVPN{settings.VPNInterface=it.Name;break}}};hub:=newEventHub();pm:=proxy.New(proxy.Config{Root:root,Host:settings.ProxyHost,Port:settings.ProxyPort,VPNInterface:settings.VPNInterface,DNSProvider:settings.DNSProvider,SingBoxVer:settings.SingBoxVer},hub.publish);token:=make([]byte,24);_,_=rand.Read(token);s:=&Server{root:root,settingsPath:settingsPath,settings:settings,pm:pm,events:hub,csrf:hex.EncodeToString(token)};_ = saveSettings(settingsPath,settings);return s,nil}
func (s *Server) Settings()Settings{s.mu.Lock();defer s.mu.Unlock();return s.settings}
func (s *Server) ListenAddr()string{return s.Settings().Listen}
func (s *Server) AutoOpen()bool{return s.Settings().AutoOpen}
func (s *Server) Root()string{return s.root}
func (s *Server) Handler()http.Handler{mux:=http.NewServeMux();mux.HandleFunc("GET /api/status",s.handleStatus);mux.HandleFunc("GET /api/events",s.handleEvents);mux.HandleFunc("GET /api/diagnostics",s.handleDiagnostics);mux.HandleFunc("GET /api/logs",s.handleLogs);mux.HandleFunc("POST /api/config",s.requireCSRF(s.handleConfig));mux.HandleFunc("POST /api/actions/install",s.requireCSRF(s.handleInstall));mux.HandleFunc("POST /api/actions/start",s.requireCSRF(s.handleStart));mux.HandleFunc("POST /api/actions/stop",s.requireCSRF(s.handleStop));mux.HandleFunc("POST /api/actions/test",s.requireCSRF(s.handleTest));mux.HandleFunc("POST /api/actions/endpoint",s.requireCSRF(s.handleEndpoint));mux.HandleFunc("POST /api/actions/launch",s.requireCSRF(s.handleLaunch));mux.HandleFunc("POST /api/actions/hosts/enable",s.requireCSRF(s.handleHostsEnable));mux.HandleFunc("POST /api/actions/hosts/disable",s.requireCSRF(s.handleHostsDisable));mux.HandleFunc("POST /api/actions/safe",s.requireCSRF(s.handleSafeMode));staticFS,_:=fs.Sub(webui.FS,"static");fileServer:=http.FileServer(http.FS(staticFS));mux.HandleFunc("GET /",func(w http.ResponseWriter,r *http.Request){http.SetCookie(w,&http.Cookie{Name:"agp_csrf",Value:s.csrf,Path:"/",SameSite:http.SameSiteStrictMode,Secure:false,HttpOnly:false});if r.URL.Path=="/"{r.URL.Path="/index.html"};fileServer.ServeHTTP(w,r)});return s.securityHeaders(mux)}
func (s *Server) securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'");next.ServeHTTP(w,r)})}
func (s *Server) requireCSRF(next http.HandlerFunc)http.HandlerFunc{return func(w http.ResponseWriter,r *http.Request){c,e:=r.Cookie("agp_csrf");if e!=nil||c.Value!=s.csrf||r.Header.Get("X-AGP-CSRF")!=s.csrf{http.Error(w,"CSRF validation failed",http.StatusForbidden);return};next(w,r)}}
func writeJSON(w http.ResponseWriter,v any){w.Header().Set("Content-Type","application/json; charset=utf-8");_ = json.NewEncoder(w).Encode(v)}
func decodeJSON(r *http.Request,v any)error{defer r.Body.Close();return json.NewDecoder(io.LimitReader(r.Body,1<<20)).Decode(v)}
func (s *Server) status(ctx context.Context)Status{ifaces,_:=platform.Interfaces();return Status{OS:runtime.GOOS,Arch:runtime.GOARCH,ProxyRunning:s.pm.Running(),ProxyURL:s.pm.HTTPProxyURL(),SOCKSURL:"socks5://"+s.pm.SOCKSProxyAddr(),SingBoxPath:s.pm.Find(),SingBoxVersion:s.pm.Version(ctx),AntigravityPath:antigravity.FindExecutable(),Settings:s.Settings(),Interfaces:ifaces}}
func (s *Server) handleStatus(w http.ResponseWriter,r *http.Request){writeJSON(w,s.status(r.Context()))}
func (s *Server) handleEvents(w http.ResponseWriter,r *http.Request){f,ok:=w.(http.Flusher);if !ok{http.Error(w,"stream unsupported",500);return};w.Header().Set("Content-Type","text/event-stream");w.Header().Set("Cache-Control","no-cache");ch,cancel:=s.events.subscribe();defer cancel();for{select{case e:=<-ch:fmt.Fprintf(w,"data: %s\n\n",eventJSON(e));f.Flush();case <-r.Context().Done():return}}}
func (s *Server) handleDiagnostics(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),35*time.Second);defer cancel();d,e:=diagnostics.Collect(ctx,targetDomains);if e!=nil{http.Error(w,e.Error(),500);return};writeJSON(w,d)}
func tail(path string,n int)string{b,e:=os.ReadFile(path);if e!=nil{return ""};lines:=strings.Split(string(b),"\n");if len(lines)>n{lines=lines[len(lines)-n:]};return strings.Join(lines,"\n")}
func (s *Server) handleLogs(w http.ResponseWriter,r *http.Request){writeJSON(w,map[string]string{"stdout":tail(s.pm.LogPath(),200),"stderr":tail(s.pm.ErrPath(),200)})}
func (s *Server) handleConfig(w http.ResponseWriter,r *http.Request){var in Settings;if e:=decodeJSON(r,&in);e!=nil{http.Error(w,e.Error(),400);return};s.mu.Lock();cur:=s.settings;if in.Listen!=""{cur.Listen=in.Listen};if in.ProxyHost!=""{cur.ProxyHost=in.ProxyHost};if in.ProxyPort>0&&in.ProxyPort<65536{cur.ProxyPort=in.ProxyPort};cur.VPNInterface=in.VPNInterface;if in.DNSProvider=="cloudflare"||in.DNSProvider=="google"{cur.DNSProvider=in.DNSProvider};if in.SingBoxVer!=""{cur.SingBoxVer=in.SingBoxVer};cur.AutoOpen=in.AutoOpen;s.settings=cur;s.mu.Unlock();s.pm.SetVPNInterface(cur.VPNInterface);s.pm.SetDNSProvider(cur.DNSProvider);_ = saveSettings(s.settingsPath,cur);s.events.publish("info","configuration updated");writeJSON(w,map[string]any{"ok":true,"settings":cur})}
func (s *Server) handleInstall(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),4*time.Minute);defer cancel();p,e:=s.pm.Install(ctx);if e!=nil{s.events.publish("error",e.Error());http.Error(w,e.Error(),500);return};writeJSON(w,map[string]any{"ok":true,"path":p,"version":s.pm.Version(ctx)})}
func (s *Server) handleStart(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),30*time.Second);defer cancel();if s.pm.Find()==""{if _,e:=s.pm.Install(ctx);e!=nil{http.Error(w,e.Error(),500);return}};if e:=s.pm.Start(ctx);e!=nil{http.Error(w,e.Error(),500);return};time.Sleep(700*time.Millisecond);writeJSON(w,map[string]any{"ok":s.pm.Running(),"proxy":s.pm.HTTPProxyURL()})}
func (s *Server) handleStop(w http.ResponseWriter,r *http.Request){if e:=s.pm.Stop();e!=nil{http.Error(w,e.Error(),500);return};s.events.publish("info","proxy stop requested");writeJSON(w,map[string]bool{"ok":true})}
func (s *Server) handleTest(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),90*time.Second);defer cancel();res:=s.pm.Tests(ctx);for _,x:=range res{lvl:="info";if !x.OK{lvl="error"};s.events.publish(lvl,x.String())};writeJSON(w,res)}
func (s *Server) handleEndpoint(w http.ResponseWriter,r *http.Request){files,e:=antigravity.ForceProductionEndpoint();if e!=nil{http.Error(w,e.Error(),500);return};s.events.publish("info",fmt.Sprintf("production endpoint applied to %d settings file(s)",len(files)));writeJSON(w,map[string]any{"ok":true,"files":files})}
func (s *Server) handleLaunch(w http.ResponseWriter,r *http.Request){if !s.pm.Running(){http.Error(w,"local proxy is not running",409);return};if e:=antigravity.LaunchWithProxy("",s.pm.HTTPProxyURL(),"socks5://"+s.pm.SOCKSProxyAddr());e!=nil{http.Error(w,e.Error(),500);return};s.events.publish("info","Antigravity launched with process-only proxy environment");writeJSON(w,map[string]bool{"ok":true})}
func (s *Server) handleHostsEnable(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),20*time.Second);defer cancel();ips:=diagnostics.TrustedA(ctx,"daily-cloudcode-pa.googleapis.com");if len(ips)==0{http.Error(w,"pinned DoH returned no A record",502);return};backup,e:=antigravity.SetHostsOverride("daily-cloudcode-pa.googleapis.com",ips[0],filepath.Join(s.root,"backups"));if e!=nil{http.Error(w,"hosts write failed (admin/root likely required): "+e.Error(),500);return};s.events.publish("warn","emergency hosts override enabled");writeJSON(w,map[string]any{"ok":true,"ip":ips[0],"backup":backup})}
func (s *Server) handleHostsDisable(w http.ResponseWriter,r *http.Request){if e:=antigravity.RemoveHostsOverride();e!=nil{http.Error(w,"hosts write failed (admin/root likely required): "+e.Error(),500);return};s.events.publish("info","emergency hosts override removed");writeJSON(w,map[string]bool{"ok":true})}
func (s *Server) handleSafeMode(w http.ResponseWriter,r *http.Request){ctx,cancel:=context.WithTimeout(r.Context(),4*time.Minute);defer cancel();if s.pm.Find()==""{if _,e:=s.pm.Install(ctx);e!=nil{http.Error(w,e.Error(),500);return}};if !s.pm.Running(){if e:=s.pm.Start(ctx);e!=nil{http.Error(w,e.Error(),500);return};time.Sleep(time.Second)};files,e:=antigravity.ForceProductionEndpoint();if e!=nil{s.events.publish("warn","endpoint override: "+e.Error())};if e:=antigravity.LaunchWithProxy("",s.pm.HTTPProxyURL(),"socks5://"+s.pm.SOCKSProxyAddr());e!=nil{http.Error(w,e.Error(),500);return};s.events.publish("info","SAFE MODE completed: proxy is process-only; system proxy untouched");writeJSON(w,map[string]any{"ok":true,"settings_files":files})}
func (s *Server) Serve(ctx context.Context)error{addr:=s.ListenAddr();ln,e:=net.Listen("tcp",addr);if e!=nil{return e};srv:=&http.Server{Handler:s.Handler(),ReadHeaderTimeout:5*time.Second,IdleTimeout:60*time.Second};go func(){<-ctx.Done();c,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();_ = srv.Shutdown(c)}();log.Printf("AntigravitiProxi UI: http://%s",addr);return srv.Serve(ln)}
