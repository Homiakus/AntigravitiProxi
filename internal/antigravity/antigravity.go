package antigravity

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var endpointRE=regexp.MustCompile(`(?m)"jetski\.cloudCodeUrl"\s*:\s*"[^"]*"`)
func SettingsCandidates()[]string{home,_:=os.UserHomeDir();out:=[]string{};if runtime.GOOS=="windows"{app:=os.Getenv("APPDATA");if app!=""{out=append(out,filepath.Join(app,"Antigravity","User","settings.json"),filepath.Join(app,"Google","Antigravity","User","settings.json"))}}else{cfg:=os.Getenv("XDG_CONFIG_HOME");if cfg==""&&home!=""{cfg=filepath.Join(home,".config")};if cfg!=""{out=append(out,filepath.Join(cfg,"Antigravity","User","settings.json"),filepath.Join(cfg,"antigravity","User","settings.json"),filepath.Join(cfg,"Google","Antigravity","User","settings.json"))}};return out}
func ForceProductionEndpoint()([]string,error){replacement:=`"jetski.cloudCodeUrl": "https://cloudcode-pa.googleapis.com"`;changed:=[]string{};candidates:=SettingsCandidates();found:=false;for _,p:=range candidates{b,e:=os.ReadFile(p);if e!=nil{continue};found=true;raw:=string(b);backup:=fmt.Sprintf("%s.backup-%s",p,time.Now().Format("20060102-150405"));_ = os.WriteFile(backup,b,0o600);var next string;if endpointRE.MatchString(raw){next=endpointRE.ReplaceAllString(raw,replacement)}else{idx:=strings.Index(raw,"{");if idx<0{return changed,fmt.Errorf("settings file is not JSON-like: %s",p)};tail:=raw[idx+1:];comma:="";if strings.TrimSpace(tail)!="}"&&strings.TrimSpace(tail)!=""{comma=","};next=raw[:idx+1]+"\n  "+replacement+comma+tail};if e=os.WriteFile(p,[]byte(next),0o600);e!=nil{return changed,e};changed=append(changed,p)};if !found&&len(candidates)>0{p:=candidates[0];if e:=os.MkdirAll(filepath.Dir(p),0o755);e!=nil{return nil,e};raw:="{\n  "+replacement+"\n}\n";if e:=os.WriteFile(p,[]byte(raw),0o600);e!=nil{return nil,e};changed=append(changed,p)};return changed,nil}
func FindExecutable()string{names:=[]string{"antigravity","antigravity-desktop"};if runtime.GOOS=="windows"{names=[]string{"Antigravity.exe","antigravity.exe"}};for _,n:=range names{if p,e:=exec.LookPath(n);e==nil{return p}};home,_:=os.UserHomeDir();var candidates []string;if runtime.GOOS=="windows"{local:=os.Getenv("LOCALAPPDATA");pf:=os.Getenv("ProgramFiles");candidates=[]string{filepath.Join(local,"Programs","Antigravity","Antigravity.exe"),filepath.Join(local,"Antigravity","Antigravity.exe"),filepath.Join(pf,"Antigravity","Antigravity.exe")}}else{candidates=[]string{"/usr/bin/antigravity","/usr/local/bin/antigravity","/opt/Antigravity/antigravity",filepath.Join(home,".local","bin","antigravity")}};for _,p:=range candidates{if st,e:=os.Stat(p);e==nil&&!st.IsDir(){return p}};return ""}
func LaunchWithProxy(exe,httpProxy,socksProxy string)error{if exe==""{exe=FindExecutable()};if exe==""{return errors.New("Antigravity executable not found")};cmd:=exec.Command(exe);env:=filteredEnv(os.Environ());no:="localhost,127.0.0.1,::1";env=append(env,"HTTP_PROXY="+httpProxy,"HTTPS_PROXY="+httpProxy,"ALL_PROXY="+socksProxy,"NO_PROXY="+no,"http_proxy="+httpProxy,"https_proxy="+httpProxy,"all_proxy="+socksProxy,"no_proxy="+no);cmd.Env=env;if e:=cmd.Start();e!=nil{return e};return cmd.Process.Release()}
func filteredEnv(in []string)[]string{keys:=map[string]bool{"HTTP_PROXY":true,"HTTPS_PROXY":true,"ALL_PROXY":true,"NO_PROXY":true};out:=make([]string,0,len(in));for _,v:=range in{p:=strings.SplitN(v,"=",2);if len(p)==2&&keys[strings.ToUpper(p[0])]{continue};out=append(out,v)};return out}
