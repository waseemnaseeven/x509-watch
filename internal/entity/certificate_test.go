package entity

import (
	"testing"
	"time"
)

func TestCertificateInfo_IsExpired(t *testing.T) {
	now := time.Now()

	c := &CertificateInfo{
		NotAfter: now.Add(-1 * time.Hour),
	}
	if !c.IsExpired(now) {
		t.Fatalf("expected certificate to be expired")
	}

	c2 := &CertificateInfo{
		NotAfter: now.Add(1 * time.Hour),
	}
	if c2.IsExpired(now) {
		t.Fatalf("expected certificate to NOT be expired")
	}
}
