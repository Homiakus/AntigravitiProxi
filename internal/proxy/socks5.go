package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5DialContext performs a minimal SOCKS5 CONNECT handshake and deliberately
// sends the hostname (ATYP=DOMAIN) to the proxy. This is the equivalent of
// curl's socks5h:// behavior and avoids local DNS resolution.
func SOCKS5DialContext(proxyAddr string, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout}; c, err := d.DialContext(ctx, "tcp", proxyAddr); if err != nil { return nil, err }
		fail := func(e error) (net.Conn, error) { _ = c.Close(); return nil, e }
		if deadline, ok := ctx.Deadline(); ok { _ = c.SetDeadline(deadline) }
		if _, err = c.Write([]byte{0x05, 0x01, 0x00}); err != nil { return fail(err) }
		resp := make([]byte, 2); if _, err = io.ReadFull(c, resp); err != nil { return fail(err) }
		if resp[0] != 0x05 || resp[1] != 0x00 { return fail(fmt.Errorf("SOCKS5 auth negotiation failed: %v", resp)) }
		host, portText, err := net.SplitHostPort(address); if err != nil { return fail(err) }
		port64, err := strconv.ParseUint(portText, 10, 16); if err != nil { return fail(err) }
		if len(host) > 255 { return fail(fmt.Errorf("hostname too long")) }
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}; req = append(req, host...); p := make([]byte, 2); binary.BigEndian.PutUint16(p, uint16(port64)); req = append(req, p...)
		if _, err = c.Write(req); err != nil { return fail(err) }
		head := make([]byte, 4); if _, err = io.ReadFull(c, head); err != nil { return fail(err) }
		if head[0] != 0x05 || head[1] != 0x00 { return fail(fmt.Errorf("SOCKS5 CONNECT failed, reply=%d", head[1])) }
		var skip int
		switch head[3] { case 0x01: skip = 4; case 0x03: n := make([]byte,1); if _,err=io.ReadFull(c,n);err!=nil{return fail(err)}; skip=int(n[0]); case 0x04: skip=16; default: return fail(fmt.Errorf("SOCKS5 invalid ATYP %d", head[3])) }
		buf := make([]byte, skip+2); if _, err = io.ReadFull(c, buf); err != nil { return fail(err) }
		_ = c.SetDeadline(time.Time{}); return c, nil
	}
}
