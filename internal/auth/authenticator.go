package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
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
	fmt.Println("Getting user information")

	key := cacheKey{
		username: username,
		action:   "userInfo",
	}
	if cachedUser, ok := a.getCache(key); ok {
		fmt.Println("user found in cache")
		return cachedUser.(*types.UserInfo), nil
	}

	searchFilter := fmt.Sprintf(a.authCfg.UserFilter, ldap.EscapeFilter(username))
	searchResp := ldap.NewSearchRequest(
		a.authCfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		a.authCfg.UserAttributes,
		nil,
	)

	searchResult, err := a.connManager.Search(bindUser, bindPassword, searchResp)
	if err != nil {
		return nil, fmt.Errorf("error while running getUserInfo function: %v", err)
	}

	if len(searchResult.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	if len(searchResult.Entries) > 1 {
		return nil, fmt.Errorf("for provided username, we got more than one user entries")
	}

	entry := searchResult.Entries[0]
	userInfo := &types.UserInfo{
		DN:          entry.DN,
		Username:    entry.GetAttributeValue("sAMAccountName"),
		DisplayName: entry.GetAttributeValue("displayName"),
		Email:       entry.GetAttributeValue("mail"),
		UPN:         entry.GetAttributeValue("userPrincipalName"),
		Groups:      entry.GetAttributeValues("memberOf"),
		Attributes:  make(map[string][]string),
	}

	for _, attr := range entry.Attributes {
		userInfo.Attributes[attr.Name] = attr.Values
	}

	a.setCache(key, userInfo)
	fmt.Println("user has been added to cache")
	return userInfo, nil
}

func (a *Authenticator) GetGroupInfo(groupName, bindUser, bindPassword string) (*types.GroupInfo, error) {
	fmt.Println("Getting group information")

	key := cacheKey{username: groupName, action: "groupInfo"}
	if cached, ok := a.getCache(key); ok {
		fmt.Println("Group information found in cache")
		return cached.(*types.GroupInfo), nil
	}

	// preparing filter for groupInformation search
	filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName))
	searchReq := ldap.NewSearchRequest(
		a.authCfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		a.authCfg.GroupAttributes,
		nil,
	)

	searchResp, err := a.connManager.Search(bindUser, bindPassword, searchReq)
	if err != nil {
		return nil, fmt.Errorf("getGroupInfo return error: %v", err)
	}

	if len(searchResp.Entries) == 0 {
		return nil, fmt.Errorf("group information not found, entries is empty")
	}

	if len(searchResp.Entries) > 1 {
		return nil, fmt.Errorf("group information is more than one")
	}

	entry := searchResp.Entries[0]

	grp := &types.GroupInfo{
		DN:          entry.DN,
		Name:        entry.GetAttributeValue("cn"),
		Description: entry.GetAttributeValue("description"),
		Attributes:  make(map[string][]string),
	}

	for _, attr := range entry.Attributes {
		grp.Attributes[attr.Name] = attr.Values
	}

	memberReq := fmt.Sprintf("(&(objectClass=user)(memberOf=%s))", ldap.EscapeFilter(grp.DN))
	memberFilter := ldap.NewSearchRequest(
		a.authCfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		memberReq,
		[]string{"distinguishedName", "sAMAccountName"},
		nil,
	)

	memberResp, err := a.connManager.Search(bindUser, bindPassword, memberFilter)
	if err == nil {
		for _, mem := range memberResp.Entries {
			grp.Members = append(grp.Members, mem.GetAttributeValue("sAMAccountName"))
		}
	} else {
		fmt.Printf("Failed to get member: %v", err)
	}

	a.setCache(key, grp)
	return grp, nil
}

func (a *Authenticator) GetUserGroups(username, bindUser, bindPassword string) ([]types.GroupInfo, error) {
	key := cacheKey{
		username: username,
		action:   "userGroups",
	}

	if cached, ok := a.getCache(key); ok {
		fmt.Println("userGroups is on cache")
		return cached.([]types.GroupInfo), nil
	}

	userInfo, err := a.GetUserInfo(username, bindUser, bindPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch user info")
	}

	var grp []types.GroupInfo
	for _, grpDN := range userInfo.Groups {
		cn := extractCN(grpDN)
		if cn == "" {
			continue
		}

		grpInfo, err := a.GetGroupInfo(cn, bindUser, bindPassword)
		if err != nil {
			fmt.Printf("failed to access user: (%s)'s group: %s || err: %v \n", userInfo.Username, cn, err)
			continue
		}

		grp = append(grp, *grpInfo)
	}

	a.setCache(key, grp)
	fmt.Printf("Found %d groups for user %s \n", len(grp), username)
	return nil, nil
}

func (a *Authenticator) ValidateSession(sessionID string) bool {
	session, valid := a.sm.GetSession(sessionID)
	return valid && session.IsValid()
}

func (a *Authenticator) RefreshSession(sessionID string) bool {
	session, valid := a.sm.GetSession(sessionID)
	if !valid {
		return false
	}

	session.Extend(a.authCfg.SessionTTL)
	session.UpdateActivity()
	return true
}

func (a *Authenticator) InvalidateSession(sessionID string) bool {
	return a.sm.InvalidSession(sessionID)
}

func (a *Authenticator) InvalidateUserSession(username string) int {
	return a.sm.InvalidUserSession(username)
}

func (a *Authenticator) Close() {
	if a.cleanupTimer != nil {
		a.cleanupTimer.Stop()
	}

	a.sm.Close()
	fmt.Println("Authenticator closed")
}

func (a *Authenticator) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	a.mu.RLock()
	// stats[]
	defer a.mu.RUnlock()
	return stats
}
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
