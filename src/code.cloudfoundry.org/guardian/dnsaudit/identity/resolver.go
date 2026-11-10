package identity

import (
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"code.cloudfoundry.org/garden/client/connection"
	"code.cloudfoundry.org/lager/v3"
)

const logConfigProperty = "log_config"

// Throttling parent cgroups that Garden may place containers under.
var throttlingCgroups = map[string]bool{"good": true, "bad": true}

type Container struct {
	Handle     string            `json:"handle"`
	Cgroup     string            `json:"cgroup,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

//go:generate counterfeiter -o fakes/property_source.go --fake-name PropertySource . PropertySource
type PropertySource interface {
	Handles() ([]string, error)
	Properties(handle string) (map[string]string, error)
}

type propertyEntry struct {
	properties map[string]string
	fetched    time.Time
	failed     bool
}

// After a failed request, Garden is asked again for the same handle only
// after this delay, so an unavailable Garden API doesn't slow down every event.
const retryAfterError = 5 * time.Second

// Resolver maps a cgroup ID to a Garden container and the configured subset of
// its properties. Keys are looked up as Garden properties first, then as tags
// of the log_config property.
type Resolver struct {
	cgroups *CgroupIndex
	source  PropertySource
	keys    []string
	ttl     time.Duration
	now     func() time.Time
	logger  lager.Logger

	handles         map[string]bool
	handlesFetched  time.Time
	minHandlesFetch time.Duration
	properties      map[string]propertyEntry

	GardenErrors   atomic.Uint64
	UnknownCgroups atomic.Uint64
}

func NewResolver(cgroups *CgroupIndex, source PropertySource, keys []string, ttl time.Duration, now func() time.Time, logger lager.Logger) *Resolver {
	return &Resolver{
		cgroups:         cgroups,
		source:          source,
		keys:            keys,
		ttl:             ttl,
		now:             now,
		logger:          logger,
		handles:         map[string]bool{},
		minHandlesFetch: time.Second,
		properties:      map[string]propertyEntry{},
	}
}

func (r *Resolver) Resolve(cgroupID uint64) (Container, bool) {
	path, ok := r.cgroups.Path(cgroupID)
	if !ok || path == "." {
		r.UnknownCgroups.Add(1)
		return Container{}, false
	}

	parts := strings.Split(path, "/")
	if throttlingCgroups[parts[0]] && len(parts) > 1 {
		parts = parts[1:]
	}
	handle := r.handleFor(parts[0])

	return Container{
		Handle:     handle,
		Cgroup:     strings.Join(parts, "/"),
		Properties: r.propertiesFor(handle),
	}, true
}

// handleFor maps the top-level cgroup name to a container handle. Processes
// with their own resources get sibling cgroups named "<handle>-<suffix>".
func (r *Resolver) handleFor(name string) string {
	if r.handles[name] {
		return name
	}
	if r.now().Sub(r.handlesFetched) >= r.minHandlesFetch {
		r.refreshHandles()
		if r.handles[name] {
			return name
		}
	}

	best := ""
	for handle := range r.handles {
		if len(handle) > len(best) && strings.HasPrefix(name, handle+"-") {
			best = handle
		}
	}
	if best != "" {
		return best
	}
	return name
}

func (r *Resolver) refreshHandles() {
	r.handlesFetched = r.now()
	handles, err := r.source.Handles()
	if err != nil {
		r.GardenErrors.Add(1)
		r.logger.Error("list-containers", err)
		return
	}
	r.handles = make(map[string]bool, len(handles))
	for _, h := range handles {
		r.handles[h] = true
	}
	for h := range r.properties {
		if !r.handles[h] {
			delete(r.properties, h)
		}
	}
}

func (r *Resolver) propertiesFor(handle string) map[string]string {
	if len(r.keys) == 0 {
		return nil
	}

	now := r.now()
	entry, ok := r.properties[handle]
	if ok && !entry.failed && now.Sub(entry.fetched) < r.ttl {
		return entry.properties
	}
	if ok && entry.failed && now.Sub(entry.fetched) < retryAfterError {
		return entry.properties
	}

	all, err := r.source.Properties(handle)
	if err != nil {
		r.GardenErrors.Add(1)
		r.logger.Error("get-properties", err, lager.Data{"handle": handle})
		r.properties[handle] = propertyEntry{properties: entry.properties, fetched: now, failed: true}
		return entry.properties
	}

	selected := Select(all, r.keys)
	r.properties[handle] = propertyEntry{properties: selected, fetched: now}
	return selected
}

// Select returns the requested keys from the properties, falling back to the
// tags of the log_config property.
func Select(all map[string]string, keys []string) map[string]string {
	var tags map[string]string
	if raw, ok := all[logConfigProperty]; ok {
		var logConfig struct {
			Tags map[string]string `json:"tags"`
		}
		if json.Unmarshal([]byte(raw), &logConfig) == nil {
			tags = logConfig.Tags
		}
	}

	selected := map[string]string{}
	for _, key := range keys {
		if value, ok := all[key]; ok {
			selected[key] = value
		} else if value, ok := tags[key]; ok {
			selected[key] = value
		}
	}
	return selected
}

type GardenSource struct {
	Connection connection.Connection
}

// NewGardenSource connects to the Garden API. Every request uses a new
// connection, so a deadline on the connection bounds the request time.
func NewGardenSource(network, address string, timeout time.Duration, logger lager.Logger) *GardenSource {
	dialer := func(string, string) (net.Conn, error) {
		conn, err := net.DialTimeout(network, address, timeout)
		if err != nil {
			return nil, err
		}
		return conn, conn.SetDeadline(time.Now().Add(timeout))
	}
	return &GardenSource{Connection: connection.NewWithDialerAndLogger(dialer, logger)}
}

func (g *GardenSource) Handles() ([]string, error) {
	return g.Connection.List(nil)
}

func (g *GardenSource) Properties(handle string) (map[string]string, error) {
	properties, err := g.Connection.Properties(handle)
	if err != nil {
		return nil, err
	}
	return properties, nil
}
