// Package auth fournit l'authentification admin sans dépendance externe :
//   - hachage de mot de passe par PBKDF2-HMAC-SHA256 (sel aléatoire, nombreuses
//     itérations) — jamais de mot de passe en clair ;
//   - jetons de session signés par HMAC-SHA256 (format compact type JWT),
//     vérifiables hors-ligne, avec expiration.
//
// Tout repose sur la bibliothèque standard (crypto/*, encoding/*).
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const pbkdf2Iter = 120000

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// pbkdf2SHA256 dérive une clé de 32 octets (un bloc HMAC-SHA256 suffit).
func pbkdf2SHA256(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1}) // index de bloc 1 (RFC 2898)
	u := mac.Sum(nil)
	out := make([]byte, len(u))
	copy(out, u)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for k := range out {
			out[k] ^= u[k]
		}
	}
	return out
}

// HashPassword renvoie une représentation autonome "pbkdf2$iter$sel$hash".
func HashPassword(pw string) string {
	salt := randomBytes(16)
	dk := pbkdf2SHA256([]byte(pw), salt, pbkdf2Iter)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk))
}

// VerifyPassword compare en temps constant (anti timing-attack).
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(pw), salt, iter)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewSecret génère un secret de signature (base64) à persister.
func NewSecret() string {
	return base64.RawStdEncoding.EncodeToString(randomBytes(32))
}

// DecodeSecret transforme le secret persisté en octets.
func DecodeSecret(s string) []byte {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return []byte(s) // repli : utiliser la chaîne telle quelle
	}
	return b
}

type claims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

// IssueToken émet un jeton signé "payload.signature" valable ttl.
func IssueToken(secret []byte, sub string, ttl time.Duration) string {
	c := claims{Sub: sub, Exp: time.Now().Add(ttl).Unix()}
	pj, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(pj)
	return payload + "." + sign(secret, payload)
}

// ParseToken vérifie la signature et l'expiration, et renvoie le sujet.
func ParseToken(secret []byte, tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return "", false
	}
	expected := sign(secret, parts[0])
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[1])) != 1 {
		return "", false
	}
	pj, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var c claims
	if json.Unmarshal(pj, &c) != nil {
		return "", false
	}
	if time.Now().Unix() > c.Exp {
		return "", false
	}
	return c.Sub, true
}

func sign(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
