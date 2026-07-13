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
	if pool == nil || len(pool.Subjects()) == 0 {
		t.Fatal("system trust store contains no certificate authorities")
	}
}
