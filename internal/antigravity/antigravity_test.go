package antigravity

import "testing"

func TestFilteredEnvRemovesAllProxyCases(t *testing.T){in:=[]string{"PATH=/bin","HTTP_PROXY=a","http_proxy=b","HTTPS_PROXY=c","NO_PROXY=d","KEEP=yes"};got:=filteredEnv(in);if len(got)!=2||got[0]!="PATH=/bin"||got[1]!="KEEP=yes"{t.Fatalf("unexpected env: %#v",got)}}
func TestRemoveHostsBlock(t *testing.T){in:="127.0.0.1 localhost\n"+hostsStart+"\n1.2.3.4 daily-cloudcode-pa.googleapis.com\n"+hostsEnd+"\n8.8.8.8 x\n";got:=removeBlock(in);if got!="127.0.0.1 localhost\n8.8.8.8 x\n"{t.Fatalf("unexpected: %q",got)}}
