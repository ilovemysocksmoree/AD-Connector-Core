package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ilovemysocksmoree/adcore/internal/connection"
	"github.com/ilovemysocksmoree/adcore/internal/types"
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

func (a *Authenticator) setCache(k cacheKey, v interface{}) {
	if !a.authCfg.CacheEnabled {
		return
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	a.cache[k] = cacheEntry{
		value:      v,
		expiration: time.Now().Add(a.authCfg.CacheTTL),
	}
}

func (a *Authenticator) getCache(k cacheKey) (interface{}, bool) {
	if !a.authCfg.CacheEnabled {
		return nil, false
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	v, doesExist := a.cache[k]
	if !doesExist || time.Now().After(v.expiration) {
		return nil, false
	}

	return v.value, true
}

func (a *Authenticator) Authenticate(username, password string) (*Session, error) {
	return nil, nil
}

func (a *Authenticator) GetUserInfo(username, bindUser, bindPassword string) (*types.UserInfo, error) {
	return nil, nil
}

func (a *Authenticator) GetGroupInfo(groupName, bindUser, bindPassword string) (*types.GroupInfo, error) {
	return nil, nil
}

func (a *Authenticator) GetUserGroups(groupName, bindUser, bindPassword string) ([]types.GroupInfo, error) {
	return nil, nil
}

func (a *Authenticator) ValidateSession(sessionID string) bool        { return false }
func (a *Authenticator) RefreshSession(sessionID string) bool         { return false }
func (a *Authenticator) InvalidateSession(sessionID string) bool      { return false }
func (a *Authenticator) InvalidateUserSession(username string) int    { return 1 }
func (a *Authenticator) Close()                                       {}
func (a *Authenticator) GetStats() map[string]interface{}             { return map[string]interface{}{} }
func (a *Authenticator) ClearCache()                                  {}
func (a *Authenticator) GetSession(sessionID string) (*Session, bool) { return nil, false }
func (a *Authenticator) GetUser(username, bindUser, bindPassword string) (*types.UserInfo, error) {
	return a.GetUserInfo("", "", "")
}
func (a *Authenticator) SearchUsers(filter, bindUser, bindPassword string) ([]*types.UserInfo, error) {
	return nil, nil
}

func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}

	return ""
}
