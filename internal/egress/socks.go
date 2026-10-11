package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// net/http detaches its connection-creation context from caller cancellation.
// Preserve the request context as a value solely for the SOCKS handshake. Stop
// observing it before returning a pooled connection, so later requests do not
// inherit the first caller's cancellation.
type requestDialContextKey struct{}

func socksConnect(ctx context.Context, network, target string, slot Slot, dial func(context.Context, string, string) (net.Conn, error)) (conn net.Conn, err error) {
	if original, ok := ctx.Value(requestDialContextKey{}).(context.Context); ok {
		ctx = original
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	failure := func(code, reason string) error {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code, reason = "proxy_timeout", "deadline"
		}
		return &EgressError{Code: code, SlotID: slot.ID, Generation: slot.TransportGeneration, Stage: "socks_handshake", Reason: reason}
	}
	host, rawPort, parseErr := net.SplitHostPort(target)
	port, portErr := strconv.Atoi(rawPort)
	if parseErr != nil || portErr != nil || port < 1 || port > 65535 || host == "" || len(host) > 255 {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	conn, err = dial(ctx, network, net.JoinHostPort(slot.Host, strconv.Itoa(slot.Port)))
	if err != nil {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	c := conn
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer func() {
		stop()
		if err != nil {
			c.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	write := func(b []byte) bool {
		for len(b) > 0 {
			n, e := c.Write(b)
			if e != nil || n == 0 {
				return false
			}
			b = b[n:]
		}
		return true
	}
	read := func(b []byte) bool { _, e := io.ReadFull(c, b); return e == nil }
	method := byte(0)
	if slot.Username != "" {
		method = 2
	}
	var response [4]byte
	if !write([]byte{5, 1, method}) || !read(response[:2]) {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	if response[0] != 5 {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	if response[1] != method {
		return nil, failure("proxy_auth_failed", "authentication_rejected")
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(slot.Username))}, []byte(slot.Username)...)
		auth = append(auth, byte(len(slot.Password)))
		auth = append(auth, []byte(slot.Password)...)
		if !write(auth) || !read(response[:2]) {
			return nil, failure("proxy_connect_failed", "socks_handshake_failed")
		}
		if response[0] != 1 || response[1] != 0 {
			return nil, failure("proxy_auth_failed", "authentication_rejected")
		}
	}
	req := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		req = append(req, 1)
		req = append(req, ip.To4()...)
	case ip != nil:
		req = append(req, 4)
		req = append(req, ip.To16()...)
	default:
		// Hostnames go to the SOCKS server unchanged; no local target DNS.
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if !write(req) || !read(response[:]) {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	if response[0] != 5 || response[2] != 0 {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	if response[1] != 0 {
		return nil, failure("proxy_connect_failed", "socks_connect_rejected")
	}
	n := 0
	switch response[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if !read(response[:1]) || response[0] == 0 {
			return nil, failure("proxy_connect_failed", "socks_handshake_failed")
		}
		n = int(response[0])
	default:
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	// Maximum 255-byte domain plus two-byte port. Never leave reply bytes in
	// the stream where the upstream HTTP/TLS parser could consume them.
	if !read(make([]byte, n+2)) {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	if !stop() || ctx.Err() != nil {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	if e := c.SetDeadline(time.Time{}); e != nil {
		return nil, failure("proxy_connect_failed", "socks_handshake_failed")
	}
	return c, nil
}
