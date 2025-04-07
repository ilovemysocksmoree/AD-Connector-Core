package connection

import (
	"sync"
	"time"
)

type Manager struct {
	pool         *ConnectionPool
	cfg          *ConnConfig
	statLock     sync.RWMutex
	connStats    map[string]int
	lastPingTime time.Time
	isHealthy    bool
}

func GetConnectionManager(config *ConnConfig) *Manager {
	if err := config.Validate(); err != nil {
		return nil
	}

	pool := NewConnectionPool(config)
	manager := &Manager{
		pool:      pool,
		cfg:       config,
		isHealthy: false,
		connStats: make(map[string]int),
	}

	return manager
}
