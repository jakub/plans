package auth_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/jakub/plans/internal/auth"
)

func TestGenerateAndVerifyToken(t *testing.T) {
	t.Parallel()

	token, digest, err := auth.GenerateToken(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if token != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("token = %q", token)
	}
	if !auth.VerifyBearer("Bearer "+token, digest) {
		t.Error("generated token did not verify")
	}
	if auth.VerifyBearer("Bearer wrong", digest) {
		t.Error("wrong token verified")
	}
	if auth.VerifyBearer(token, digest) {
		t.Error("header without bearer scheme verified")
	}
}

func TestDigestRoundTrip(t *testing.T) {
	t.Parallel()

	want := sha256.Sum256([]byte("token"))
	encoded := auth.DigestHex(want)
	got, err := auth.ParseDigest(encoded)
	if err != nil {
		t.Fatalf("ParseDigest() error = %v", err)
	}
	if got != want {
		t.Errorf("digest = %x, want %x", got, want)
	}
	if _, err := auth.ParseDigest("too-short"); err == nil {
		t.Error("ParseDigest() accepted an invalid digest")
	}
}
