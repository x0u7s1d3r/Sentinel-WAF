package auth

import (
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	h := HashPassword("correct horse battery staple")
	if !VerifyPassword("correct horse battery staple", h) {
		t.Error("le bon mot de passe devrait être validé")
	}
	if VerifyPassword("mauvais", h) {
		t.Error("un mauvais mot de passe ne doit jamais passer")
	}
	// Deux hachages du même mot de passe diffèrent (sel aléatoire).
	if h == HashPassword("correct horse battery staple") {
		t.Error("le sel doit rendre chaque hachage unique")
	}
}

func TestTokens(t *testing.T) {
	secret := DecodeSecret(NewSecret())

	tok := IssueToken(secret, "admin", time.Hour)
	if sub, ok := ParseToken(secret, tok); !ok || sub != "admin" {
		t.Errorf("jeton valide rejeté (sub=%q ok=%v)", sub, ok)
	}

	// Mauvais secret -> rejet.
	if _, ok := ParseToken(DecodeSecret(NewSecret()), tok); ok {
		t.Error("un jeton signé par un autre secret doit être rejeté")
	}

	// Jeton falsifié -> rejet.
	if _, ok := ParseToken(secret, tok+"x"); ok {
		t.Error("un jeton altéré doit être rejeté")
	}

	// Jeton expiré -> rejet.
	expired := IssueToken(secret, "admin", -time.Minute)
	if _, ok := ParseToken(secret, expired); ok {
		t.Error("un jeton expiré doit être rejeté")
	}
}
