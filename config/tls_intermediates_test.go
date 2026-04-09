package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.viam.com/test"

	"go.viam.com/rdk/logging"
	rutils "go.viam.com/rdk/utils"
)

// makeSelfSignedCert creates a minimal self-signed certificate and returns the
// tls.Certificate and the PEM-encoded certificate string.
func makeSelfSignedCert(t *testing.T, aiaURLs []string) (tls.Certificate, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.That(t, err, test.ShouldBeNil)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: aiaURLs,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	test.That(t, err, test.ShouldBeNil)

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyBytes, err := x509.MarshalECPrivateKey(key)
	test.That(t, err, test.ShouldBeNil)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	test.That(t, err, test.ShouldBeNil)

	return tlsCert, certPEM
}

// makeFakeIntermediateDER returns the DER bytes of a self-signed cert to use as a
// stand-in intermediate in tests.
func makeFakeIntermediateDER(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.That(t, err, test.ShouldBeNil)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fake-intermediate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	test.That(t, err, test.ShouldBeNil)
	return der
}

func TestLoadOrFetchIntermediateCerts(t *testing.T) {
	t.Run("cache hit", func(t *testing.T) {
		dir := t.TempDir()
		origDir := rutils.ViamDotDir
		rutils.ViamDotDir = dir
		defer func() { rutils.ViamDotDir = origDir }()

		cert, leafPEM := makeSelfSignedCert(t, nil)
		intermediateDER := makeFakeIntermediateDER(t)

		// Pre-populate cache.
		partID := "test-part"
		cache := intermediateTLSCertCache{
			LeafCertPEM:   leafPEM,
			Intermediates: [][]byte{intermediateDER},
		}
		data, err := json.Marshal(cache)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, os.WriteFile(getTLSCacheFilePath(partID), data, 0o640), test.ShouldBeNil)

		loadOrFetchIntermediateCerts(&cert, leafPEM, partID, logging.NewTestLogger(t))

		// Leaf + cached intermediate should be present.
		test.That(t, len(cert.Certificate), test.ShouldEqual, 2)
		test.That(t, cert.Certificate[1], test.ShouldResemble, intermediateDER)
	})

	t.Run("cache miss no AIA URLs", func(t *testing.T) {
		dir := t.TempDir()
		origDir := rutils.ViamDotDir
		rutils.ViamDotDir = dir
		defer func() { rutils.ViamDotDir = origDir }()

		// Cert has no AIA URLs so fetch returns nothing.
		cert, leafPEM := makeSelfSignedCert(t, nil)
		partID := "test-part"

		loadOrFetchIntermediateCerts(&cert, leafPEM, partID, logging.NewTestLogger(t))

		// Only the leaf should be present; no cache file written.
		test.That(t, len(cert.Certificate), test.ShouldEqual, 1)
		_, err := os.Stat(getTLSCacheFilePath(partID))
		test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
	})

	t.Run("cache miss fetches and caches", func(t *testing.T) {
		intermediateDER := makeFakeIntermediateDER(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			_, _ = w.Write(intermediateDER)
		}))
		defer server.Close()

		dir := t.TempDir()
		origDir := rutils.ViamDotDir
		rutils.ViamDotDir = dir
		defer func() { rutils.ViamDotDir = origDir }()

		cert, leafPEM := makeSelfSignedCert(t, []string{server.URL})
		partID := "test-part"

		loadOrFetchIntermediateCerts(&cert, leafPEM, partID, logging.NewTestLogger(t))

		// Intermediate should be appended.
		test.That(t, len(cert.Certificate), test.ShouldEqual, 2)
		test.That(t, cert.Certificate[1], test.ShouldResemble, intermediateDER)

		// Cache file should have been written.
		cached, err := readIntermediateTLSCertCache(getTLSCacheFilePath(partID))
		test.That(t, err, test.ShouldBeNil)
		test.That(t, cached.LeafCertPEM, test.ShouldEqual, leafPEM)
		test.That(t, len(cached.Intermediates), test.ShouldEqual, 1)
		test.That(t, cached.Intermediates[0], test.ShouldResemble, intermediateDER)
	})

	t.Run("leaf rotated does not use stale cache", func(t *testing.T) {
		dir := t.TempDir()
		origDir := rutils.ViamDotDir
		rutils.ViamDotDir = dir
		defer func() { rutils.ViamDotDir = origDir }()

		partID := "test-part"

		// Write cache with a different (old) leaf PEM.
		_, oldLeafPEM := makeSelfSignedCert(t, nil)
		oldIntermediate := makeFakeIntermediateDER(t)
		cache := intermediateTLSCertCache{
			LeafCertPEM:   oldLeafPEM,
			Intermediates: [][]byte{oldIntermediate},
		}
		data, err := json.Marshal(cache)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, os.WriteFile(getTLSCacheFilePath(partID), data, 0o640), test.ShouldBeNil)

		// New cert with no AIA URLs — fetch will return nothing.
		newCert, newLeafPEM := makeSelfSignedCert(t, nil)

		loadOrFetchIntermediateCerts(&newCert, newLeafPEM, partID, logging.NewTestLogger(t))

		// Old cached intermediate should NOT be used; fetch returned nothing so only leaf.
		test.That(t, len(newCert.Certificate), test.ShouldEqual, 1)
	})

	t.Run("corrupt JSON cache falls back to fetch", func(t *testing.T) {
		dir := t.TempDir()
		origDir := rutils.ViamDotDir
		rutils.ViamDotDir = dir
		defer func() { rutils.ViamDotDir = origDir }()

		partID := "test-part"
		test.That(t, os.WriteFile(getTLSCacheFilePath(partID), []byte("not json"), 0o640), test.ShouldBeNil)

		cert, leafPEM := makeSelfSignedCert(t, nil)
		loadOrFetchIntermediateCerts(&cert, leafPEM, partID, logging.NewTestLogger(t))

		// Falls back to fetch (returns nothing due to no AIA); only leaf present.
		test.That(t, len(cert.Certificate), test.ShouldEqual, 1)
	})

	t.Run("corrupt DER in cache re-fetches from AIA", func(t *testing.T) {
		intermediateDER := makeFakeIntermediateDER(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/pkix-cert")
			_, _ = w.Write(intermediateDER)
		}))
		defer server.Close()

		dir := t.TempDir()
		origDir := rutils.ViamDotDir
		rutils.ViamDotDir = dir
		defer func() { rutils.ViamDotDir = origDir }()

		// Cert has AIA URL pointing at the mock server so re-fetch can succeed.
		cert, leafPEM := makeSelfSignedCert(t, []string{server.URL})
		partID := "test-part"

		// Write cache with the correct leaf PEM but a corrupt intermediate DER.
		cache := intermediateTLSCertCache{
			LeafCertPEM:   leafPEM,
			Intermediates: [][]byte{[]byte("not a valid DER cert")},
		}
		data, err := json.Marshal(cache)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, os.WriteFile(getTLSCacheFilePath(partID), data, 0o640), test.ShouldBeNil)

		loadOrFetchIntermediateCerts(&cert, leafPEM, partID, logging.NewTestLogger(t))

		// Corrupt DER triggers re-fetch from AIA; fresh intermediate should be present.
		test.That(t, len(cert.Certificate), test.ShouldEqual, 2)
		test.That(t, cert.Certificate[1], test.ShouldResemble, intermediateDER)
	})
}

func TestIntermediateTLSCertCache(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "cache.json")

		intermediateDER := makeFakeIntermediateDER(t)
		original := &intermediateTLSCertCache{
			LeafCertPEM:   "some-pem",
			Intermediates: [][]byte{intermediateDER},
		}

		test.That(t, writeIntermediateTLSCertCache(path, original), test.ShouldBeNil)

		read, err := readIntermediateTLSCertCache(path)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, read.LeafCertPEM, test.ShouldEqual, original.LeafCertPEM)
		test.That(t, read.Intermediates, test.ShouldResemble, original.Intermediates)
	})
}
