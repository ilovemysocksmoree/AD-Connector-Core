package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/ilovemysocksmoree/adcore/internal/connection"
)

type cacheKey struct {
	username string
	action   string
}

type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

type Authenticator struct {
	connManager  *connection.Manager
	authCfg      *AuthConfig
	sm           *SessionManager
	cache        map[cacheKey]cacheEntry
	mu           sync.RWMutex
	cleanupTimer *time.Timer
}

func NewAuthenticator(cm *connection.Manager, cfg *AuthConfig) (*Authenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("baseDN is empty")
	}

	if cm == nil {
		return nil, fmt.Errorf("connection manager is nil")
	}

	sm := NewSessionManager(cfg.SessionTTL)
	authenticator := &Authenticator{
		connManager: cm,
		authCfg:     cfg,
		sm:          sm,
		cache:       make(map[cacheKey]cacheEntry),
	}

	if cfg.CacheEnabled {
		authenticator.startCacheCleanup()
	}

	return authenticator, nil
}

func (a *Authenticator) startCacheCleanup() {
	a.cleanupTimer = time.AfterFunc(5*time.Minute, func() {
		a.cleanupCache()
		a.startCacheCleanup()
	})
}

func (a *Authenticator) cleanupCache() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	count := 0

	for k, v := range a.cache {
		if now.After(v.expiration) {
			delete(a.cache, k)
			count++
		}
	}

	if count > 0 {
		fmt.Printf("cleaned-up no.of: %d cache \n", count)
	}

}
