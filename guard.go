package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// A sealed installation defends itself. Two root daemons run: the proxy and
// a warden. Each puts back the other's program, launchd entry and loaded
// state, both keep the hosts entries and the sealed lock in place, and the
// files carry the system immutable flag so that removing them fails until
// the flag is cleared first.
//
// None of this stops someone with root who reads this file. It turns removal
// from two commands into a script that has to get several things right at
// once, which is the most a program can do against its own administrator.

const (
	wardenLabel  = daemonLabel + ".warden"
	wardenPlist  = "/Library/LaunchDaemons/" + wardenLabel + ".plist"
	wardenBinary = "/Library/PrivilegedHelperTools/" + wardenLabel
	daemonLog    = "/Library/Logs/youtube-hider.log"

	systemImmutable = 0x00020000 // SF_IMMUTABLE: only root can clear it
	guardEvery      = 5 * time.Second
)

// service is one launchd daemon: where its entry and program live and which
// subcommand it runs.
type service struct {
	label, plist, binary, arg string
}

func services(st *store) (proxy, warden service) {
	proxy = service{daemonLabel, daemonPlist, st.path(filepath.Join("bin", "ythider")), "serve"}
	warden = service{wardenLabel, wardenPlist, wardenBinary, "guard"}
	return proxy, warden
}

func (s service) xml() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + s.label + `</string>
	<key>ProgramArguments</key>
	<array><string>` + s.binary + `</string><string>` + s.arg + `</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>` + daemonLog + `</string>
</dict>
</plist>
`
}

// sealedLock returns the lock file's bytes when the installation is sealed.
func sealedLock(st *store) ([]byte, bool) {
	raw, err := os.ReadFile(st.path("lock.json"))
	if err != nil {
		return nil, false
	}
	var lk lock
	if json.Unmarshal(raw, &lk) != nil || lk.Cooloff >= 0 {
		return nil, false
	}
	return raw, true
}

func fileFlags(path string) (uint32, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, err
	}
	return st.Flags, nil
}

// protect sets an immutable flag on a file; unprotect clears it. A flag of
// zero means protection is off and both do nothing.
func protect(path string, flag uint32) error {
	have, err := fileFlags(path)
	if err != nil || flag == 0 || have&flag != 0 {
		return err
	}
	return syscall.Chflags(path, int(have|flag))
}

func unprotect(path string, flag uint32) error {
	have, err := fileFlags(path)
	if err != nil || have&flag == 0 {
		return err
	}
	return syscall.Chflags(path, int(have&^flag))
}

// replaceProtected swaps in new content for a file that may be immutable.
func replaceProtected(path string, src io.Reader, mode os.FileMode, flag uint32) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	unprotect(tmp, flag)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	unprotect(path, flag)
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return protect(path, flag)
}

// guardian is one daemon's half of the mutual watch.
type guardian struct {
	st         *store
	self, peer service
	lock       []byte   // the sealed lock, which never changes again
	config     []byte   // the machine setup, fixed at install
	policy     policy   // the last policy seen; it may only grow from here
	exe        *os.File // this program, held open so it outlives its own file
	launchctl  func(args ...string) error
	flag       uint32
	passes     int
	peerDown   bool // whether the last pass found the peer unloaded
}

func newGuardian(st *store, self, peer service, lock []byte) (*guardian, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exe, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	config, _ := os.ReadFile(st.path("config.json"))
	st.flag = systemImmutable
	return &guardian{
		st: st, self: self, peer: peer, lock: lock, config: config, policy: st.policy(),
		exe: exe, flag: systemImmutable,
		launchctl: func(args ...string) error { return run("launchctl", args...) },
	}, nil
}

func (g *guardian) run() {
	for {
		g.check()
		time.Sleep(guardEvery)
	}
}

// check is one pass: put back whatever is missing, then make sure the other
// daemon is loaded.
func (g *guardian) check() {
	for _, svc := range []service{g.self, g.peer} {
		g.keepBinary(svc)
		g.keepFile(svc.plist, []byte(svc.xml()), 0o644)
	}
	g.keepFile(g.st.path("lock.json"), g.lock, 0o600)
	if g.config != nil {
		g.keepFile(g.st.path("config.json"), g.config, 0o600)
	}
	g.keepPolicy()
	protect(g.st.path("appeals.json"), g.flag)

	// A daemon disabled in launchd stays down across restarts, so both are
	// re-enabled now and then even while they are running.
	if g.passes%12 == 0 {
		g.launchctl("enable", "system/"+g.self.label)
		g.launchctl("enable", "system/"+g.peer.label)
	}
	g.passes++
	if g.launchctl("print", "system/"+g.peer.label) == nil {
		g.peerDown = false
		return
	}
	g.launchctl("enable", "system/"+g.peer.label)
	if err := g.launchctl("bootstrap", "system", g.peer.plist); err != nil {
		if !g.peerDown { // said once, not every five seconds
			log.Printf("guard: %s is down and did not come back: %v", g.peer.label, err)
		}
		g.peerDown = true
		return
	}
	g.peerDown = false
	log.Printf("guard: %s was down; started again", g.peer.label)
}

// keepBinary restores a program that has gone missing, from this process's
// own open copy. A program that is present is left alone, whatever its
// content, so an upgrade is never undone.
func (g *guardian) keepBinary(svc service) {
	if _, err := os.Lstat(svc.binary); err == nil {
		protect(svc.binary, g.flag)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		return
	}
	info, err := g.exe.Stat()
	if err != nil {
		log.Printf("guard: %v", err)
		return
	}
	if err := replaceProtected(svc.binary, io.NewSectionReader(g.exe, 0, info.Size()), 0o755, g.flag); err != nil {
		log.Printf("guard: restoring %s: %v", svc.binary, err)
		return
	}
	log.Printf("guard: %s was missing; restored", svc.binary)
}

func (g *guardian) keepFile(path string, want []byte, mode os.FileMode) {
	if have, err := os.ReadFile(path); err == nil && bytes.Equal(have, want) {
		protect(path, g.flag)
		return
	}
	if err := replaceProtected(path, bytes.NewReader(want), mode, g.flag); err != nil {
		log.Printf("guard: restoring %s: %v", path, err)
		return
	}
	log.Printf("guard: %s was missing or changed; restored", path)
}

// keepPolicy holds the policy file to the rule the policy page enforces: a
// sealed policy only grows. A version that drops or rewrites anything the
// last one said is replaced by the last one.
func (g *guardian) keepPolicy() {
	path := g.st.path("policy.json")
	var now policy
	raw, err := os.ReadFile(path)
	if err == nil && json.Unmarshal(raw, &now) == nil &&
		strings.HasPrefix(now.Allowed, strings.TrimSpace(g.policy.Allowed)) &&
		strings.HasPrefix(now.Blocked, strings.TrimSpace(g.policy.Blocked)) {
		g.policy = now
		protect(path, g.flag)
		return
	}
	if g.policy.empty() && errors.Is(err, os.ErrNotExist) {
		return // not written yet
	}
	if err := g.st.write("policy.json", g.policy); err != nil {
		log.Printf("guard: restoring the policy: %v", err)
		return
	}
	log.Printf("guard: the policy was removed or rewritten outside the policy page; restored")
}

// arm installs this build as both daemons of a sealed installation and
// (re)starts them. Sealing and upgrading both end here.
func arm(st *store) error {
	if err := requireRoot(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	proxy, warden := services(st)
	for _, svc := range []service{proxy, warden} {
		in, err := os.Open(self)
		if err != nil {
			return err
		}
		err = replaceProtected(svc.binary, in, 0o755, systemImmutable)
		in.Close()
		if err != nil {
			return err
		}
		if err := replaceProtected(svc.plist, bytes.NewReader([]byte(svc.xml())), 0o644, systemImmutable); err != nil {
			return err
		}
	}
	if err := protect(st.path("lock.json"), systemImmutable); err != nil {
		return err
	}
	for _, svc := range []service{warden, proxy} {
		run("launchctl", "enable", "system/"+svc.label)
		if run("launchctl", "print", "system/"+svc.label) != nil {
			if err := run("launchctl", "bootstrap", "system", svc.plist); err != nil {
				return err
			}
			continue
		}
		if err := run("launchctl", "kickstart", "-k", "system/"+svc.label); err != nil {
			return err
		}
	}
	return nil
}
