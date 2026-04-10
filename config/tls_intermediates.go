package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"go.viam.com/utils"

	"go.viam.com/rdk/logging"
	rutils "go.viam.com/rdk/utils"
)

// intermediateTLSCertCache is the on-disk structure for caching intermediate TLS certificates.
// Intermediates are stored as raw DER bytes; encoding/json marshals []byte as base64.
type intermediateTLSCertCache struct {
	LeafCertPEM   string   `json:"leaf_cert_pem"`
	Intermediates [][]byte `json:"intermediates"`
}

func getTLSCacheFilePath(partID string) string {
	return filepath.Join(rutils.ViamDotDir, fmt.Sprintf("cached_tls_intermediates_%s.json", partID))
}

func readIntermediateTLSCertCache(path string) (*intermediateTLSCertCache, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer utils.UncheckedErrorFunc(f.Close)
	var c intermediateTLSCertCache
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func writeIntermediateTLSCertCache(path string, c *intermediateTLSCertCache) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	//nolint:gosec
	return os.WriteFile(path, data, 0o640)
}

// fetchIntermediateCerts fetches intermediate certificates by following the AIA
// (Authority Information Access) URLs in the leaf certificate, returning their
// DER-encoded bytes. This ensures clients that do not perform AIA fetching
// can verify the chain without needing the intermediates in their system trust store.
func fetchIntermediateCerts(ctx context.Context, cert *tls.Certificate, logger logging.Logger) [][]byte {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		logger.Debugw("failed to parse leaf certificate; skipping intermediate fetch", "error", err)
		return nil
	}

	var intermediates [][]byte
	client := &http.Client{Timeout: 10 * time.Second}
	for _, aiaURL := range leaf.IssuingCertificateURL {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, aiaURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Debugw("failed to fetch intermediate cert", "url", aiaURL, "error", err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		utils.UncheckedError(resp.Body.Close())
		if err != nil {
			logger.Debugw("failed to read intermediate cert", "url", aiaURL, "error", err)
			continue
		}
		if block, _ := pem.Decode(body); block != nil {
			body = block.Bytes
		}
		if _, err := x509.ParseCertificate(body); err != nil {
			logger.Debugw("failed to parse intermediate cert", "url", aiaURL, "error", err)
			continue
		}
		intermediates = append(intermediates, body)
	}
	return intermediates
}

// loadOrFetchIntermediateCerts appends intermediate certificates to cert, using a disk
// cache keyed by leafCertPEM to avoid redundant AIA HTTP fetches. If the leaf cert PEM
// matches the cache, cached intermediates are used and no network request is made. If
// the leaf has rotated or no cache exists, intermediates are fetched via AIA and the
// cache is updated. partID is used to name the cache file; if empty, caching is skipped.
func loadOrFetchIntermediateCerts(ctx context.Context, cert *tls.Certificate, leafCertPEM, partID string, logger logging.Logger) {
	if partID == "" {
		cert.Certificate = append(cert.Certificate, fetchIntermediateCerts(ctx, cert, logger)...)
		return
	}

	cachePath := getTLSCacheFilePath(partID)

	cached, err := readIntermediateTLSCertCache(cachePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		logger.Debugw("no TLS intermediate cache found; fetching from AIA")
	case err != nil:
		logger.Warnw("error reading TLS intermediate cache; fetching from AIA", "error", err)
	case cached.LeafCertPEM == leafCertPEM:
		logger.Debugw("TLS intermediate cache hit; skipping AIA fetch")
		validIntermediates := make([][]byte, 0, len(cached.Intermediates))
		cacheValid := true
		for _, encodedCert := range cached.Intermediates {
			if _, err := x509.ParseCertificate(encodedCert); err != nil {
				logger.Warnw("cached intermediate cert is invalid; re-fetching from AIA", "error", err)
				cacheValid = false
				break
			}
			validIntermediates = append(validIntermediates, encodedCert)
		}
		if cacheValid {
			cert.Certificate = append(cert.Certificate, validIntermediates...)
			return
		}
	default:
		logger.Debugw("leaf cert rotated; re-fetching intermediates from AIA")
	}

	fetched := fetchIntermediateCerts(ctx, cert, logger)
	if len(fetched) == 0 {
		return
	}

	cert.Certificate = append(cert.Certificate, fetched...)

	newCache := intermediateTLSCertCache{
		LeafCertPEM:   leafCertPEM,
		Intermediates: fetched,
	}
	if err := writeIntermediateTLSCertCache(cachePath, &newCache); err != nil {
		logger.Warnw("failed to write TLS intermediate cache", "error", err)
	}
}
