package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	daemonLabel    = "org.mathetic.youtube-hider"
	daemonPlist    = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	systemKeychain = "/Library/Keychains/System.keychain"
	hostsFile      = "/etc/hosts"
	hostsBegin     = "# >>> youtube-hider (managed: edits are reverted while installed)"
	hostsEnd       = "# <<< youtube-hider"
)

// hostsWith returns the hosts file content with the managed block present or
// absent. When present, any other line that maps an intercepted host is
// dropped, since an earlier entry would win over the managed one.
func hostsWith(current string, enabled bool) string {
	var keep []string
	inBlock := false
	for _, line := range strings.Split(current, "\n") {
		switch {
		case strings.HasPrefix(line, "# >>> youtube-hider"):
			inBlock = true
			continue
		case strings.HasPrefix(line, "# <<< youtube-hider"):
			inBlock = false
			continue
		case inBlock:
			continue
		case enabled && mapsIntercepted(line):
			continue
		}
		keep = append(keep, line)
	}
	out := strings.TrimRight(strings.Join(keep, "\n"), "\n") + "\n"
	if enabled {
		names := strings.Join(interceptHosts, " ")
		out += hostsBegin + "\n127.0.0.1 " + names + "\n::1 " + names + "\n" + hostsEnd + "\n"
	}
	return out
}

func mapsIntercepted(line string) bool {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	for _, name := range fields[1:] {
		if intercepted(strings.ToLower(name)) {
			return true
		}
	}
	return false
}

func setHosts(enabled bool) (changed bool, err error) {
	raw, err := os.ReadFile(hostsFile)
	if err != nil {
		return false, err
	}
	want := hostsWith(string(raw), enabled)
	if want == string(raw) {
		return false, nil
	}
	if err := os.WriteFile(hostsFile, []byte(want), 0o644); err != nil {
		return false, err
	}
	exec.Command("dscacheutil", "-flushcache").Run()
	exec.Command("killall", "-HUP", "mDNSResponder").Run()
	return true, nil
}

// guardHosts keeps the hosts entries in place for as long as the daemon runs.
func guardHosts() {
	for {
		if changed, err := setHosts(true); err != nil {
			log.Printf("hosts: %v", err)
		} else if changed {
			log.Printf("hosts: entries restored")
		}
		time.Sleep(3 * time.Second)
	}
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command changes system files; run it with sudo")
	}
	return nil
}

// copyFile writes dst as a new file and renames it into place. macOS ties a
// running binary's code signature to its file, so the daemon's binary must
// be replaced, never overwritten.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// upgrade swaps the running daemon's binary for this one and restarts it.
// The policy, the lock and the certificate authority are left as they are.
func upgrade(st *store) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(st.path("lock.json")); err != nil {
		return errors.New("not installed; run `sudo ythider install`")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := copyFile(self, st.path(filepath.Join("bin", "ythider")), 0o755); err != nil {
		return err
	}
	return run("launchctl", "kickstart", "-k", "system/"+daemonLabel)
}

func plistXML(binary string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + daemonLabel + `</string>
	<key>ProgramArguments</key>
	<array><string>` + binary + `</string><string>serve</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>/Library/Logs/youtube-hider.log</string>
</dict>
</plist>
`
}

// install sets up the daemon, the constrained certificate authority and the
// lock. The generated password is never printed.
func install(st *store, cfg config, cooloff time.Duration, never bool) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(st.path("lock.json")); err == nil {
		return errors.New("already installed; `sudo ythider unlock` removes it")
	}
	for _, addr := range listenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s is in use by another program (%v); youtube-hider needs it", addr, err)
		}
		ln.Close()
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(st.path("bin"), 0o700); err != nil {
		return err
	}
	binary := st.path(filepath.Join("bin", "ythider"))
	if err := copyFile(self, binary, 0o755); err != nil {
		return err
	}
	if err := st.write("config.json", cfg); err != nil {
		return err
	}
	if err := createAuthority(st.path("ca")); err != nil {
		return err
	}
	fmt.Println("macOS will ask you to approve trusting a certificate that is valid for YouTube domains only.")
	if err := run("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", systemKeychain, st.path("ca/root.pem")); err != nil {
		os.RemoveAll(st.dir)
		return fmt.Errorf("the certificate was not trusted, so nothing was installed: %w", err)
	}
	lk, err := newLock(newPassword(), cooloff, never)
	if err != nil {
		return err
	}
	if err := st.write("lock.json", lk); err != nil {
		return err
	}
	if err := os.WriteFile(daemonPlist, []byte(plistXML(binary)), 0o644); err != nil {
		return err
	}
	return run("launchctl", "bootstrap", "system", daemonPlist)
}

// uninstall removes everything install created. Callers verify the password.
func uninstall(st *store) error {
	if err := requireRoot(); err != nil {
		return err
	}
	exec.Command("launchctl", "bootout", "system/"+daemonLabel).Run()
	os.Remove(daemonPlist)
	if _, err := setHosts(false); err != nil {
		return err
	}
	if fp, err := rootFingerprint(st.path("ca")); err == nil {
		exec.Command("security", "remove-trusted-cert", "-d", st.path("ca/root.pem")).Run()
		exec.Command("security", "delete-certificate", "-Z", fp, systemKeychain).Run()
	}
	return os.RemoveAll(st.dir)
}
