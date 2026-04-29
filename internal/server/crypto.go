package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// LoadOrCreateServerSecret reads a 32-byte server secret from path or creates
// it. If the file exists but cannot be read or is truncated, the function
// returns an error instead of silently overwriting it: losing this key
// invalidates every existing challenge AnswerHash.
func LoadOrCreateServerSecret(path string) ([]byte, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if info.Mode().Perm()&0077 != 0 {
			_ = os.Chmod(path, 0600)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("server.key exists but cannot be read (%w); refusing to overwrite", rerr)
		}
		if len(data) < 32 {
			return nil, fmt.Errorf("server.key exists but is truncated (%d bytes); refusing to overwrite", len(data))
		}
		return data[:32], nil
	case errors.Is(err, fs.ErrNotExist):
		// fall through to generate
	default:
		return nil, fmt.Errorf("stat server.key: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := atomicWrite(path, secret, 0600); err != nil {
		return nil, fmt.Errorf("write server.key: %w", err)
	}
	return secret, nil
}

// atomicWrite writes data to path via a temp file + fsync + rename so the
// final file is either fully present or absent — never truncated.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op if rename succeeded
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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
