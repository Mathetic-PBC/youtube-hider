package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// resolver looks up the real addresses of the intercepted hosts. It speaks
// DNS directly, because the system resolver (and Go's) would read /etc/hosts
// and hand the proxy its own loopback address.
type resolver struct {
	servers []string

	mu    sync.Mutex
	cache map[string]dnsEntry
}

type dnsEntry struct {
	addrs   []string
	expires time.Time
}

func newResolver() *resolver {
	servers := systemNameservers("/etc/resolv.conf")
	servers = append(servers, "1.1.1.1", "8.8.8.8")
	return &resolver{servers: servers, cache: map[string]dnsEntry{}}
}

func systemNameservers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip := net.ParseIP(strings.SplitN(fields[1], "%", 2)[0])
			if ip != nil && !ip.IsLoopback() {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func (r *resolver) lookup(ctx context.Context, host string) ([]string, error) {
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.addrs, nil
	}
	r.mu.Unlock()

	var lastErr error
	for _, server := range r.servers {
		v4, ttl, err := queryDNS(ctx, server, host, dnsmessage.TypeA)
		if err != nil {
			lastErr = err
			continue
		}
		v6, _, _ := queryDNS(ctx, server, host, dnsmessage.TypeAAAA)
		addrs := append(v4, v6...)
		if len(addrs) == 0 {
			lastErr = errors.New("no addresses for " + host)
			continue
		}
		ttl = min(max(ttl, 30*time.Second), 10*time.Minute)
		r.mu.Lock()
		r.cache[host] = dnsEntry{addrs: addrs, expires: time.Now().Add(ttl)}
		r.mu.Unlock()
		return addrs, nil
	}
	return nil, lastErr
}

func queryDNS(ctx context.Context, server, host string, qtype dnsmessage.Type) ([]string, time.Duration, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, 0, err
	}
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	if _, err := conn.Write(packed); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(buf[:n])
	if err != nil {
		return nil, 0, err
	}
	if hdr.ID != id {
		return nil, 0, errors.New("dns: response id mismatch")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, err
	}
	var addrs []string
	ttl := time.Hour
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return nil, 0, err
			}
			addrs = append(addrs, net.IP(a.A[:]).String())
			ttl = min(ttl, time.Duration(h.TTL)*time.Second)
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err != nil {
				return nil, 0, err
			}
			addrs = append(addrs, net.IP(a.AAAA[:]).String())
			ttl = min(ttl, time.Duration(h.TTL)*time.Second)
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, err
			}
		}
	}
	return addrs, ttl, nil
}

// dial connects to the real upstream for an intercepted host, trying each
// resolved address in turn.
func (r *resolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := r.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 4 * time.Second}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
