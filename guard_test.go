package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const userImmutable = 0x2 // UF_IMMUTABLE: what a test can set without root

// testGuardian builds a guardian over a temporary directory, with launchctl
// replaced by a recorder. loaded says whether the peer daemon is loaded.
func testGuardian(t *testing.T, loaded *bool) (*guardian, *[]string) {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error {
			unprotect(p, userImmutable)
			return nil
		})
	})
	st := &store{dir: filepath.Join(dir, "state"), flag: userImmutable}
	os.MkdirAll(st.dir, 0o755)
	lk, err := newLock(newPassword(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.write("lock.json", lk); err != nil {
		t.Fatal(err)
	}
	raw, sealed := sealedLock(st)
	if !sealed {
		t.Fatal("a lock made with never=true should read as sealed")
	}
	exePath := filepath.Join(dir, "exe")
	os.WriteFile(exePath, []byte("the program"), 0o755)
	exe, err := os.Open(exePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exe.Close() })

	self := service{"test.proxy", filepath.Join(dir, "daemons", "proxy.plist"), filepath.Join(dir, "bin", "proxy"), "serve"}
	peer := service{"test.warden", filepath.Join(dir, "daemons", "warden.plist"), filepath.Join(dir, "helpers", "warden"), "guard"}
	var calls []string
	g := &guardian{st: st, self: self, peer: peer, lock: raw, exe: exe, flag: userImmutable}
	g.launchctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "print" && !*loaded {
			return os.ErrNotExist
		}
		return nil
	}
	return g, &calls
}

func TestGuardRestoresWhatIsRemoved(t *testing.T) {
	loaded := true
	g, _ := testGuardian(t, &loaded)
	g.check()

	files := []string{g.self.binary, g.peer.binary, g.self.plist, g.peer.plist, g.st.path("lock.json")}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("first pass should create %s: %v", f, err)
		}
		if err := os.Remove(f); err == nil {
			t.Fatalf("%s should be immutable, but it was removed", f)
		}
	}
	// Someone clears the flags and deletes everything, including the lock.
	for _, f := range files {
		unprotect(f, userImmutable)
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	g.check()
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was not restored: %v", f, err)
		}
	}
	if got, _ := os.ReadFile(g.peer.binary); string(got) != "the program" {
		t.Errorf("restored program = %q", got)
	}
	if _, sealed := sealedLock(g.st); !sealed {
		t.Error("the restored lock should still be sealed")
	}
	if got, _ := os.ReadFile(g.peer.plist); !strings.Contains(string(got), g.peer.binary) || !strings.Contains(string(got), "<string>guard</string>") {
		t.Errorf("restored launchd entry is wrong:\n%s", got)
	}
}

func TestGuardPutsBackAChangedLockButNotAChangedProgram(t *testing.T) {
	loaded := true
	g, _ := testGuardian(t, &loaded)
	g.check()

	// An unsealed lock written over the sealed one is reverted.
	lockPath := g.st.path("lock.json")
	unprotect(lockPath, userImmutable)
	os.WriteFile(lockPath, []byte(`{"cooloff_seconds":1,"sealed":"known"}`), 0o600)
	// A program replaced by an upgrade is kept.
	unprotect(g.self.binary, userImmutable)
	os.WriteFile(g.self.binary, []byte("a newer build"), 0o755)
	g.check()

	if _, sealed := sealedLock(g.st); !sealed {
		t.Error("a replaced lock should be put back")
	}
	if got, _ := os.ReadFile(g.self.binary); string(got) != "a newer build" {
		t.Errorf("an upgraded program was overwritten: %q", got)
	}
	if err := os.Remove(g.self.binary); err == nil {
		t.Error("the upgraded program should be immutable again")
	}
}

func TestGuardRevivesTheOtherDaemon(t *testing.T) {
	loaded := true
	g, calls := testGuardian(t, &loaded)
	g.check()
	for _, c := range *calls {
		if strings.HasPrefix(c, "bootstrap") {
			t.Fatalf("a loaded daemon should be left alone, got %q", c)
		}
	}
	*calls = nil
	loaded = false
	g.check()
	got := strings.Join(*calls, "\n")
	for _, want := range []string{"print system/test.warden", "enable system/test.warden", "bootstrap system " + g.peer.plist} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSealedStoreStillTakesWrites(t *testing.T) {
	loaded := true
	g, _ := testGuardian(t, &loaded)
	for _, allowed := range []string{"talks", "talks\nmath"} {
		if err := g.st.write("policy.json", policy{Allowed: allowed}); err != nil {
			t.Fatalf("writing the policy of a sealed installation: %v", err)
		}
		g.check() // the guard re-flags the file between writes
	}
	if got := g.st.policy().Allowed; got != "talks\nmath" {
		t.Errorf("policy = %q", got)
	}
	if err := os.Remove(g.st.path("policy.json")); err == nil {
		t.Error("the policy file should be immutable between writes")
	}
}

func TestUnsealedLockIsNotGuarded(t *testing.T) {
	st := &store{dir: t.TempDir()}
	lk, _ := newLock(newPassword(), 0, false)
	st.write("lock.json", lk)
	if _, sealed := sealedLock(st); sealed {
		t.Error("a lock with a cool-off should not read as sealed")
	}
}

func TestGuardLetsThePolicyGrowButNotShrink(t *testing.T) {
	loaded := true
	g, _ := testGuardian(t, &loaded)
	g.check() // nothing written yet: nothing to restore
	if _, err := os.Stat(g.st.path("policy.json")); err == nil {
		t.Fatal("the guard should not invent a policy")
	}
	g.st.write("policy.json", policy{Allowed: "talks", Blocked: "politics"})
	g.check()
	g.st.write("policy.json", policy{Allowed: "talks\nmath", Blocked: "politics\nprank videos"})
	g.check()
	if got := g.st.policy(); got.Allowed != "talks\nmath" || got.Blocked != "politics\nprank videos" {
		t.Fatalf("an addition was not kept: %+v", got)
	}
	// Written from outside: the ban list emptied, the allow list widened.
	g.st.write("policy.json", policy{Allowed: "everything", Blocked: ""})
	g.check()
	if got := g.st.policy(); got.Allowed != "talks\nmath" || got.Blocked != "politics\nprank videos" {
		t.Errorf("a rewritten policy was kept: %+v", got)
	}
	unprotect(g.st.path("policy.json"), userImmutable)
	os.Remove(g.st.path("policy.json"))
	g.check()
	if got := g.st.policy(); got.Blocked != "politics\nprank videos" {
		t.Errorf("a deleted policy was not restored: %+v", got)
	}
}
