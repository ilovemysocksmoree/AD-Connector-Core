package auth

import "time"

type cacheKey struct {
	username string
	action   string
}

type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

type Authenticator struct {
}
