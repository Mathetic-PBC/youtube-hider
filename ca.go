package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// interceptHosts are the only hostnames the proxy answers for. Everything
// else on the machine is untouched.
var interceptHosts = []string{
	"www.youtube.com",
	"youtube.com",
	"m.youtube.com",
	"youtu.be",
	"www.youtube-nocookie.com",
}

// caDomains are the name constraints baked into both CA certificates. A
// certificate for any other domain signed by this CA is invalid, so the
// trusted root cannot be used to intercept anything but YouTube.
var caDomains = []string{"youtube.com", "youtu.be", "youtube-nocookie.com"}

const rootCN = "youtube-hider local root"

type authority struct {
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	leafKey  *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// createAuthority writes root.pem, intermediate.pem and intermediate.key into
// dir. The root's private key is never written anywhere: it signs the
// intermediate and is dropped, so the trusted root can sign nothing further.
func createAuthority(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: rootCN, Organization: []string{"youtube-hider"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(10, 0, 0),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  1,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         caDomains,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	interTmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "youtube-hider local intermediate", Organization: []string{"youtube-hider"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(10, 0, 0),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         caDomains,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(interKey)
	if err != nil {
		return err
	}
	files := []struct {
		name  string
		block *pem.Block
		mode  os.FileMode
	}{
		{"root.pem", &pem.Block{Type: "CERTIFICATE", Bytes: rootDER}, 0o644},
		{"intermediate.pem", &pem.Block{Type: "CERTIFICATE", Bytes: interDER}, 0o644},
		{"intermediate.key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}, 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), pem.EncodeToMemory(f.block), f.mode); err != nil {
			return err
		}
	}
	return nil
}

func readPEM(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data", path)
	}
	return block.Bytes, nil
}

func loadAuthority(dir string) (*authority, error) {
	interDER, err := readPEM(filepath.Join(dir, "intermediate.pem"))
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	keyDER, err := readPEM(filepath.Join(dir, "intermediate.key"))
	if err != nil {
		return nil, err
	}
	interKey, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &authority{inter: inter, interKey: interKey, leafKey: leafKey, leaves: map[string]*tls.Certificate{}}, nil
}

// rootFingerprint returns the SHA-1 of the root certificate, which is how the
// macOS keychain identifies it.
func rootFingerprint(dir string) (string, error) {
	der, err := readPEM(filepath.Join(dir, "root.pem"))
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func intercepted(host string) bool {
	for _, h := range interceptHosts {
		if h == host {
			return true
		}
	}
	return false
}

func (a *authority) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(hello.ServerName)
	if !intercepted(host) {
		return nil, errors.New("not an intercepted host: " + host)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leaves[host]; ok && time.Until(c.Leaf.NotAfter) > 24*time.Hour {
		return c, nil
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, 30),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.inter, &a.leafKey.PublicKey, a.interKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.inter.Raw}, PrivateKey: a.leafKey, Leaf: leaf}
	a.leaves[host] = c
	return c, nil
}
