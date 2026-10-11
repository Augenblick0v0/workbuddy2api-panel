package panel

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestProxyOAuthSOCKS(t *testing.T) {
	f := newProxyOAuthFixture(t)
	slot := f.manager.Snapshot().Slots["slot-2"]
	target := net.JoinHostPort(slot.Host, strconv.Itoa(slot.Port))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var b [4]byte
				if _, e := io.ReadFull(c, b[:3]); e != nil || b != [4]byte{5, 1, 0, 0} {
					return
				}
				c.Write([]byte{5, 0})
				if _, e := io.ReadFull(c, b[:]); e != nil {
					return
				}
				n := 4
				switch b[3] {
				case 4:
					n = 16
				case 3:
					if _, e := io.ReadFull(c, b[:1]); e != nil {
						return
					}
					n = int(b[0])
				}
				if _, e := io.CopyN(io.Discard, c, int64(n+2)); e != nil {
					return
				}
				// Always tunnel to the synthetic OAuth handler, never internet.
				dst, e := net.DialTimeout("tcp", target, time.Second)
				if e != nil {
					return
				}
				defer dst.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				go func() { io.Copy(dst, c); dst.Close() }()
				io.Copy(c, dst)
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	_, err = f.manager.Update(f.manager.Snapshot().Revision, func(c *egress.Config) error {
		s := c.Slots["slot-2"]
		s.Scheme, s.Host, s.Port = "socks5h", "127.0.0.1", port
		c.Slots["slot-2"] = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertOAuthDone(t, f.poll(t, f.start(t)))
	for _, path := range []string{"/fixture/state", "/fixture/token", "/fixture/account"} {
		if f.count("B", path) != 1 || f.count("A", path) != 0 {
			t.Fatalf("SOCKS OAuth route mismatch for %s", path)
		}
	}
	if !f.bindingWritten.Load() || f.manager.Snapshot().Bindings["oauth-fixture-uid"] != "slot-2" {
		t.Fatal("SOCKS OAuth did not preserve durable binding order")
	}
}
