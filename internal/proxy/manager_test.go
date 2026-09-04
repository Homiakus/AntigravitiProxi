package proxy

import "testing"

func TestAssetNameFor(t *testing.T) {
	cases := []struct{ os, arch, want string }{{"windows","amd64","sing-box-1.13.1-windows-amd64.zip"},{"windows","arm64","sing-box-1.13.1-windows-arm64.zip"},{"linux","amd64","sing-box-1.13.1-linux-amd64.tar.gz"},{"linux","arm64","sing-box-1.13.1-linux-arm64.tar.gz"}}
	for _,c:=range cases{if got:=assetNameFor(c.os,c.arch,"1.13.1");got!=c.want{t.Fatalf("%s/%s: got %q want %q",c.os,c.arch,got,c.want)}}
}
