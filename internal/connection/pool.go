package connection

import (
	"context"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ConnectionState int

const (
	ConnectionStateIdle ConnectionState = iota
	ConnectionStateInUse
	ConnectionStateClosed
)

type PooledConnection struct {
	conn       *ldap.Conn
	state      ConnectionState
	boundDN    string
	boundCreds string
	lastUsed   time.Time
	createdAt  time.Time
	isBound    bool
}

type ConnectionPool struct {
	config      *ConnConfig
	connections []*PooledConnection
	mu          sync.Mutex
}

func NewConnectionPool(config *ConnConfig) *ConnectionPool {
	return &ConnectionPool{
		config:      config,
		connections: make([]*PooledConnection, 0, config.MaxConnection),
	}
}

func (p *ConnectionPool) createNewConnection(ctx context.Context) (*PooledConnection, error) {

	return nil, nil
}
