//go:build linux

package internetprobe

import (
	"crypto/x509"
	"testing"
)

func TestSystemTrustStoreContainsCertificates(t *testing.T) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("load system trust store: %v", err)
	}
	if pool == nil || pool.Equal(x509.NewCertPool()) {
		t.Fatal("system trust store contains no certificate authorities")
	}
}
