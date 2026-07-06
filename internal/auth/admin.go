package auth

import (
	"sync"
	"time"
)

// Admin porte l'état d'authentification admin, modifiable à chaud (création du
// compte au premier lancement, changement de mot de passe). Thread-safe.
// La persistance se fait via un callback `save` (aucune dépendance au stockage).
type Admin struct {
	mu     sync.RWMutex
	hash   string
	secret []byte
	save   func(hash string)
}

// NewAdmin construit l'état à partir d'un hachage existant (vide si aucun compte)
// et d'un secret de signature. `save` persiste le hachage (peut être nil).
func NewAdmin(hash string, secret []byte, save func(string)) *Admin {
	return &Admin{hash: hash, secret: secret, save: save}
}

// Enabled indique qu'un compte admin existe (donc l'auth est requise).
func (a *Admin) Enabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.hash != ""
}

// Verify valide un mot de passe contre le hachage courant.
func (a *Admin) Verify(pw string) bool {
	a.mu.RLock()
	h := a.hash
	a.mu.RUnlock()
	return h != "" && VerifyPassword(pw, h)
}

// SetPassword (re)définit le mot de passe : hachage puis persistance.
func (a *Admin) SetPassword(pw string) {
	h := HashPassword(pw)
	a.mu.Lock()
	a.hash = h
	a.mu.Unlock()
	if a.save != nil {
		a.save(h)
	}
}

// Token émet un jeton de session signé.
func (a *Admin) Token(ttl time.Duration) string {
	a.mu.RLock()
	s := a.secret
	a.mu.RUnlock()
	return IssueToken(s, "admin", ttl)
}

// Valid vérifie un jeton de session.
func (a *Admin) Valid(tok string) bool {
	a.mu.RLock()
	s := a.secret
	a.mu.RUnlock()
	_, ok := ParseToken(s, tok)
	return ok
}
