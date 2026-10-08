// Package auth implements upload bearer-token generation and verification.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const tokenBytes = 32

// GenerateToken returns a cryptographically random bearer token and its SHA-256 digest.
func GenerateToken(random io.Reader) (string, [sha256.Size]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	buffer := make([]byte, tokenBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("read cryptographic randomness: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buffer)

	return token, sha256.Sum256([]byte(token)), nil
}

// ParseDigest parses a hexadecimal SHA-256 token digest.
func ParseDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return digest, fmt.Errorf("decode upload token digest: %w", err)
	}
	if len(decoded) != sha256.Size {
		return digest, errors.New("upload token digest must contain 64 hexadecimal characters")
	}
	copy(digest[:], decoded)

	return digest, nil
}

// DigestHex returns the hexadecimal digest stored by the server.
func DigestHex(digest [sha256.Size]byte) string {
	return hex.EncodeToString(digest[:])
}

// VerifyBearer verifies an Authorization header without revealing comparison timing.
func VerifyBearer(header string, expected [sha256.Size]byte) bool {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.Contains(token, " ") {
		return false
	}
	actual := sha256.Sum256([]byte(token))

	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}
