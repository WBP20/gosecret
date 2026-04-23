package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// LoadOrCreateServerSecret reads a 32-byte server secret from path or creates it.
func LoadOrCreateServerSecret(path string) ([]byte, error) {
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm()&0077 != 0 {
			_ = os.Chmod(path, 0600)
		}
		if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
			return data[:32], nil
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0600); err != nil {
		return nil, err
	}
	return secret, nil
}

// NormalizeAnswer lowercases, strips accents, collapses whitespace and trims.
func NormalizeAnswer(in string) string {
	t := transform.Chain(
		norm.NFD,
		runes.Remove(runes.In(unicode.Mn)),
		norm.NFC,
	)
	out, _, err := transform.String(t, in)
	if err != nil {
		out = in
	}
	out = strings.ToLower(out)
	out = strings.Join(strings.Fields(out), " ")
	return strings.TrimSpace(out)
}

// AnswerHash computes HMAC-SHA256(serverSecret, salt || normalizedAnswer).
// Using the secret id as salt binds the hash to a specific secret so that
// identical answers across secrets produce different hashes.
func AnswerHash(serverSecret []byte, secretID, answer string) []byte {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write([]byte(secretID))
	mac.Write([]byte{0x00})
	mac.Write([]byte(NormalizeAnswer(answer)))
	return mac.Sum(nil)
}

func HashEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// RandomID returns a URL-safe 128-bit random identifier.
func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
