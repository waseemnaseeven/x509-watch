package entity

import (
	"time"
)

type CertInfo struct {
	FilePath   string
	CommonName string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
}

// Return time expiration (negative if already expired)
func (c *CertInfo) ExpiresInSeconds(now time.Time) float64 {
	return c.NotAfter.Sub(now).Seconds()
}

// Return elapsed time since beginning validity
func (c *CertInfo) ValidSinceSeconds(now time.Time) float64 {
	return now.Sub(c.NotBefore).Seconds()
}

// Indicate if certificate expire now
func (c *CertInfo) IsExpired(now time.Time) bool {
	return now.After(c.NotAfter)
}
