package discovery

import (
	"sync"
	"time"

	"github.com/ilovemysocksmoree/adcore/internal/connection"
)

type ForestInfo struct {
	Name                string
	RootDomain          string
	ForestFunctionLevel string
	DomainNamingMaster  string
	GlobalCatalogs      []string
	SchemaMaster        string
	DomainCount         int
	Sites               []string
	SchemaVersion       string
	CreationTime        time.Time
	ExtraAttributes     map[string][]string
}

type ForestDiscovery struct {
	connManager *connection.Manager
	cache       map[string]*ForestInfo
	cachemu     sync.RWMutex
	cachettl    time.Duration
}

func NewForestDiscovery(conn *connection.Manager) *ForestDiscovery {
	return &ForestDiscovery{
		connManager: conn,
		cache:       make(map[string]*ForestInfo),
		cachemu:     sync.RWMutex{},
		cachettl:    30 * time.Minute,
	}
}
