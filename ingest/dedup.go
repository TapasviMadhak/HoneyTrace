package main

import "crypto/sha256"
import "encoding/hex"

func hashEvent(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{"|"[0]})
	}
	return hex.EncodeToString(hash.Sum(nil))
}
