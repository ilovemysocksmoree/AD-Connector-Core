package auth

import (
	"sync"
	"time"
)

type SessionManager struct {
	sessions     map[string]*Session
	mu           sync.RWMutex
	defaultTTL   time.Duration
	cleanupTimer *time.Timer
}

func NewSessionManager(defaultTTL time.Duration) *SessionManager {
	return &SessionManager{
		sessions:   make(map[string]*Session),
		defaultTTL: defaultTTL,
	}
}
