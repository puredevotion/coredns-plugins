package geoscore

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeValkey is just enough of a RESP3 server for ValkeyStore: HELLO,
// CLIENT, CLUSTER SLOTS (all slots on itself when cluster is set, else the
// error a standalone server gives) and MGET. It lets the store's read path
// run without a real Valkey, in both topologies valkey-go distinguishes.
type fakeValkey struct {
	ln      net.Listener
	data    map[string]string
	cluster bool
	mu      sync.Mutex
	mgets   int
	wg      sync.WaitGroup
}

func startFakeValkey(t *testing.T, cluster bool, data map[string]string) *fakeValkey {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeValkey{ln: ln, data: data, cluster: cluster}
	f.wg.Add(1)
	go f.accept()
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
		f.wg.Wait()
	})
	return f
}

func (f *fakeValkey) addr() string { return f.ln.Addr().String() }

func (f *fakeValkey) accept() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go f.serve(c)
	}
}

func (f *fakeValkey) serve(c net.Conn) {
	defer f.wg.Done()
	defer c.Close() //nolint:errcheck // test server; the client sees any failure
	r := bufio.NewReader(c)
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		if _, err := io.WriteString(c, f.reply(args)); err != nil {
			return
		}
	}
}

func (f *fakeValkey) reply(args []string) string {
	if len(args) == 0 {
		return "-ERR empty command\r\n"
	}
	switch strings.ToUpper(args[0]) {
	case "HELLO":
		return "%3\r\n+server\r\n+valkey\r\n+version\r\n+6.2.0\r\n+proto\r\n:3\r\n"
	case "CLUSTER":
		if !f.cluster {
			return "-ERR This instance has cluster support disabled\r\n"
		}
		_, port, err := net.SplitHostPort(f.addr())
		if err != nil {
			return "-ERR " + err.Error() + "\r\n"
		}
		return "*1\r\n*3\r\n:0\r\n:16383\r\n*2\r\n$9\r\n127.0.0.1\r\n:" + port + "\r\n"
	case "MGET":
		f.mu.Lock()
		f.mgets++
		f.mu.Unlock()
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(args)-1)
		for _, k := range args[1:] {
			if v, ok := f.data[k]; ok {
				fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(v), v)
			} else {
				b.WriteString("_\r\n")
			}
		}
		return b.String()
	case "PING":
		return "+PONG\r\n"
	}
	return "+OK\r\n"
}

// readCommand reads one RESP array of bulk strings.
func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err //nolint:wrapcheck // test helper
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected %q", line)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err //nolint:wrapcheck // test helper
	}
	args := make([]string, 0, n)
	for range n {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err //nolint:wrapcheck // test helper
		}
		l, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(hdr, "$")))
		if err != nil {
			return nil, err //nolint:wrapcheck // test helper
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err //nolint:wrapcheck // test helper
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

// R12, R25: the store reads every key of a name, standalone or clustered.
// In cluster mode a name's keys hash to different slots, and one MGET across
// slots makes the valkey-go command builder panic; the store must split the
// read by slot instead.
func TestValkeyStoreFake(t *testing.T) {
	keys := []string{"geoscore:www.example.com:eu1", "geoscore:www.example.com:us1", "geoscore:www.example.com:ap1"}
	data := map[string]string{keys[0]: "one", keys[2]: "three"}
	for _, cluster := range []bool{false, true} {
		t.Run(fmt.Sprintf("cluster=%v", cluster), func(t *testing.T) {
			f := startFakeValkey(t, cluster, data)
			s, err := NewValkeyStore(ValkeyConfig{Addrs: []string{f.addr()}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cerr := s.Close(); cerr != nil {
					t.Error(cerr)
				}
			})
			vals, err := s.Get(t.Context(), keys)
			if err != nil {
				t.Fatal(err)
			}
			if len(vals) != 3 || string(vals[0]) != "one" || vals[1] != nil || string(vals[2]) != "three" {
				t.Fatalf("got %q", vals)
			}
		})
	}
}
