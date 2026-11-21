package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultStateDir = "/Library/Application Support/youtube-hider"

// config is machine setup chosen at install time.
type config struct {
	Model  string `json:"model"`
	Ollama string `json:"ollama"`
}

const (
	defaultModel  = "gemma4:e4b"
	defaultOllama = "http://127.0.0.1:11434"
)

// policy is what the user wrote during onboarding. The repository ships no
// policy: the classifier reads exactly these two descriptions.
type policy struct {
	Allowed string `json:"allowed"`
	Blocked string `json:"blocked"`
}

func (p policy) empty() bool { return strings.TrimSpace(p.Allowed) == "" }

// lock holds the unlock password. The password is generated at install time
// and never displayed; Sealed keeps it for a delayed reveal unless the
// cool-off is disabled, in which case it exists nowhere.
type lock struct {
	Salt        []byte     `json:"salt"`
	Hash        []byte     `json:"hash"`
	Iterations  int        `json:"iterations"`
	Cooloff     int64      `json:"cooloff_seconds"` // negative: never reveal
	Sealed      string     `json:"sealed,omitempty"`
	RequestedAt *time.Time `json:"unlock_requested_at,omitempty"`
}

const pbkdfIterations = 600_000

func newPassword() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

func normalizePassword(pw string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(pw)))
}

func newLock(password string, cooloff time.Duration, never bool) (*lock, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hash, err := pbkdf2.Key(sha256.New, normalizePassword(password), salt, pbkdfIterations, 32)
	if err != nil {
		return nil, err
	}
	l := &lock{Salt: salt, Hash: hash, Iterations: pbkdfIterations, Cooloff: int64(cooloff / time.Second)}
	if never {
		l.Cooloff = -1
	} else {
		l.Sealed = password
	}
	return l, nil
}

func (l *lock) verify(password string) bool {
	hash, err := pbkdf2.Key(sha256.New, normalizePassword(password), l.Salt, l.Iterations, len(l.Hash))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(hash, l.Hash) == 1
}

// remaining reports how long until the password may be revealed.
func (l *lock) remaining(now time.Time) (time.Duration, error) {
	if l.Cooloff < 0 {
		return 0, errors.New("this lock is sealed: no copy of the password exists")
	}
	if l.RequestedAt == nil {
		return 0, errors.New("no unlock requested; run `request-unlock` to start the cool-off")
	}
	left := l.RequestedAt.Add(time.Duration(l.Cooloff) * time.Second).Sub(now)
	return max(left, 0), nil
}

// store is the state directory. A non-zero flag means the installation is
// sealed and its files are kept immutable between writes.
type store struct {
	dir  string
	flag uint32
}

func (s *store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *store) read(name string, v any) error {
	raw, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *store) write(name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, target := s.path(name+".tmp"), s.path(name)
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	unprotect(target, s.flag)
	if err := os.Rename(tmp, target); err != nil {
		// The guard may have re-flagged the file in between; once more.
		unprotect(target, s.flag)
		if err = os.Rename(tmp, target); err != nil {
			return err
		}
	}
	protect(target, s.flag)
	return nil
}

func (s *store) config() config {
	c := config{Model: defaultModel, Ollama: defaultOllama}
	s.read("config.json", &c)
	return c
}

func (s *store) policy() policy {
	var p policy
	s.read("policy.json", &p)
	return p
}

// lock returns nil when no lock is installed (development mode).
func (s *store) lock() (*lock, error) {
	var l lock
	err := s.read("lock.json", &l)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock.json: %w", err)
	}
	return &l, nil
}
