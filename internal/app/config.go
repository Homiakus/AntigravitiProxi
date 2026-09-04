package app

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Settings struct { Listen string `json:"listen"`; ProxyHost string `json:"proxy_host"`; ProxyPort int `json:"proxy_port"`; VPNInterface string `json:"vpn_interface"`; DNSProvider string `json:"dns_provider"`; SingBoxVer string `json:"sing_box_version"`; AutoOpen bool `json:"auto_open"` }
func defaultSettings()Settings{return Settings{Listen:"127.0.0.1:48765",ProxyHost:"127.0.0.1",ProxyPort:7890,DNSProvider:"cloudflare",SingBoxVer:"1.13.1",AutoOpen:true}}
func loadSettings(path string)Settings{s:=defaultSettings();b,e:=os.ReadFile(path);if e!=nil{return s};_ = json.Unmarshal(b,&s);if s.Listen==""{s.Listen="127.0.0.1:48765"};if s.ProxyHost==""{s.ProxyHost="127.0.0.1"};if s.ProxyPort==0{s.ProxyPort=7890};if s.DNSProvider==""{s.DNSProvider="cloudflare"};if s.SingBoxVer==""{s.SingBoxVer="1.13.1"};return s}
func saveSettings(path string,s Settings)error{if e:=os.MkdirAll(filepath.Dir(path),0o755);e!=nil{return e};b,e:=json.MarshalIndent(s,"","  ");if e!=nil{return e};return os.WriteFile(path,append(b,'\n'),0o600)}
