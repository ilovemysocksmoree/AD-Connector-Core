package auth

import (
	"sync"
	"time"
)

type SessionState int

const (
	SessionStateActive SessionState = iota
	SessionStateExpired
	SessionStateInvalid
)

type Session struct {
	ID           string
	Username     string
	DN           string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	State        SessionState
	Permissions  []string
	Metadata     map[string]string
	mutex        sync.Mutex
}

func NewSession(username, dn string, duration time.Duration) *Session {
	now := time.Now()
	return &Session{
		ID:           generateSession(),
		Username:     username,
		DN:           dn,
		CreatedAt:    now,
		ExpiresAt:    now.Add(duration),
		LastActivity: now,
		State:        SessionStateActive,
		Permissions:  []string{},
		Metadata:     make(map[string]string),
	}
}

func generateSession() string {
	return "session-" + time.Now().Format("20060102150405.000")
}
