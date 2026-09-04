package antigravity

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Homiakus/AntigravitiProxi/internal/platform"
)

const hostsStart="# >>> ANTIGRAVITI-PROXI >>>"
const hostsEnd="# <<< ANTIGRAVITI-PROXI <<<"
func SetHostsOverride(domain,ip,backupDir string)(string,error){p:=platform.HostsPath();b,e:=os.ReadFile(p);if e!=nil{return "",e};if e=os.MkdirAll(backupDir,0o755);e!=nil{return "",e};backup:=fmt.Sprintf("%s/hosts-%s.bak",strings.TrimRight(backupDir,"/\\"),time.Now().Format("20060102-150405"));if e=os.WriteFile(backup,b,0o600);e!=nil{return "",e};raw:=removeBlock(string(b));raw=strings.TrimRight(raw,"\r\n")+"\n"+hostsStart+"\n"+ip+"    "+domain+"\n"+hostsEnd+"\n";return backup,os.WriteFile(p,[]byte(raw),0o644)}
func RemoveHostsOverride()error{p:=platform.HostsPath();b,e:=os.ReadFile(p);if e!=nil{return e};return os.WriteFile(p,[]byte(removeBlock(string(b))),0o644)}
func removeBlock(s string)string{re:=regexp.MustCompile(`(?s)`+regexp.QuoteMeta(hostsStart)+`.*?`+regexp.QuoteMeta(hostsEnd)+`\s*`);return re.ReplaceAllString(s,"")}
