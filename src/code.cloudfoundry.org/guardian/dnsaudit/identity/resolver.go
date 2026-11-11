package identity

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/client/connection"
	"code.cloudfoundry.org/lager/v3"
)

const logConfigProperty = "log_config"

// Throttling parent cgroups that Garden may place containers under
// (GoodCgroupName and BadCgroupName in rundmc/cgroups).
var throttlingCgroups = map[string]bool{"good": true, "bad": true}

const (
	// Run refreshes the containers and their properties at this interval, and
	// sooner when Resolve sees a container it doesn't know.
	refreshInterval = 5 * time.Second

	// After a failed request, Garden is asked again for the properties of the
	// same container only after this delay.
	retryAfterError = 5 * time.Second

	// How long Resolve waits for the properties of a container it sees for the
	// first time, while Garden is answering.
	firstLookupWait = 250 * time.Millisecond

	// Bound on the cgroup names remembered as already waited for.
	maxWaited = 10000
)

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

// Resolver maps a cgroup ID to a Garden container and the configured subset of
// its properties. Keys are looked up as Garden properties first, then as tags
// of the log_config property.
//
// Garden is only called by Refresh, which Run calls in the background, so a
// slow or unavailable Garden API doesn't hold up Resolve. For a container it
// doesn't know yet, Resolve asks Run for a refresh and, while Garden is
// answering, waits up to firstLookupWait for it, once per cgroup name. That
// wait blocks the caller.
type Resolver struct {
	cgroups *CgroupIndex
	source  PropertySource
	keys    []string
	ttl     time.Duration
	now     func() time.Time
	logger  lager.Logger
	wake    chan struct{}

	mu         sync.Mutex
	handles    map[string]bool
	properties map[string]propertyEntry
	healthy    bool
	started    uint64
	completed  uint64
	refreshed  chan struct{}
	waited     map[string]bool

	GardenErrors      atomic.Uint64
	UnknownCgroups    atomic.Uint64
	MissingProperties atomic.Uint64
}

func NewResolver(cgroups *CgroupIndex, source PropertySource, keys []string, ttl time.Duration, now func() time.Time, logger lager.Logger) *Resolver {
	return &Resolver{
		cgroups:    cgroups,
		source:     source,
		keys:       keys,
		ttl:        ttl,
		now:        now,
		logger:     logger,
		wake:       make(chan struct{}, 1),
		handles:    map[string]bool{},
		properties: map[string]propertyEntry{},
		refreshed:  make(chan struct{}),
		waited:     map[string]bool{},
	}
}

// Resolve returns the container of a cgroup. It is not safe for concurrent
// use, but may run concurrently with Run.
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

	handle, properties, known := r.lookup(parts[0])
	if !known {
		handle, properties, _ = r.waitFor(parts[0])
	}
	if properties == nil && len(r.keys) > 0 {
		r.MissingProperties.Add(1)
	}

	return Container{
		Handle:     handle,
		Cgroup:     strings.Join(parts, "/"),
		Properties: properties,
	}, true
}

// lookup maps a top-level cgroup name to a container handle and its cached
// properties. Processes with their own resources get a sibling cgroup named
// after the process ID chosen by the client; Diego names them
// "<handle>-<suffix>". It reports false when the handle or, if properties are
// configured, its properties haven't been fetched yet.
func (r *Resolver) lookup(name string) (string, map[string]string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	handle := r.match(name)
	if handle == "" {
		return name, nil, false
	}
	if len(r.keys) == 0 {
		return handle, nil, true
	}
	entry, ok := r.properties[handle]
	return handle, entry.properties, ok
}

func (r *Resolver) match(name string) string {
	if r.handles[name] {
		return name
	}
	best := ""
	for handle := range r.handles {
		if len(handle) > len(best) && strings.HasPrefix(name, handle+"-") {
			best = handle
		}
	}
	return best
}

// waitFor asks for a refresh and, the first time it sees name and while Garden
// is answering, waits up to firstLookupWait for a refresh that started after
// the request.
func (r *Resolver) waitFor(name string) (string, map[string]string, bool) {
	r.mu.Lock()
	first := !r.waited[name]
	if first {
		if len(r.waited) >= maxWaited {
			r.waited = map[string]bool{}
		}
		r.waited[name] = true
	}
	wait := first && r.healthy
	target := r.started + 1
	r.mu.Unlock()

	if !first {
		return r.lookup(name)
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	if !wait {
		return r.lookup(name)
	}

	timeout := time.NewTimer(firstLookupWait)
	defer timeout.Stop()
	for {
		r.mu.Lock()
		done, refreshed := r.completed >= target, r.refreshed
		r.mu.Unlock()
		if done {
			return r.lookup(name)
		}
		select {
		case <-refreshed:
		case <-timeout.C:
			return r.lookup(name)
		}
	}
}

// Run calls Refresh every refreshInterval and when Resolve asks for it, until
// stop is closed.
func (r *Resolver) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		case <-r.wake:
		}
		r.Refresh()
	}
}

// Refresh lists the containers and fetches the properties of new containers
// and of those whose cached properties are older than the TTL. It stops at
// the first Garden error and continues on the next refresh.
func (r *Resolver) Refresh() {
	r.mu.Lock()
	r.started++
	generation := r.started
	r.mu.Unlock()
	defer r.finish(generation)

	list, err := r.source.Handles()
	if err != nil {
		r.gardenError("list-containers", err, nil)
		return
	}
	handles := make(map[string]bool, len(list))
	for _, h := range list {
		handles[h] = true
	}

	r.mu.Lock()
	for h := range r.properties {
		if !handles[h] {
			delete(r.properties, h)
		}
	}
	var due []string
	if len(r.keys) > 0 {
		now := r.now()
		for _, h := range list {
			if r.due(h, now) {
				due = append(due, h)
			}
		}
	}
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.handles = handles
		r.mu.Unlock()
	}()

	for _, h := range due {
		all, err := r.source.Properties(h)
		var notFound garden.ContainerNotFoundError
		switch {
		case errors.As(err, &notFound):
			delete(handles, h)
		case err != nil:
			r.mu.Lock()
			r.properties[h] = propertyEntry{properties: r.properties[h].properties, fetched: r.now(), failed: true}
			r.mu.Unlock()
			r.gardenError("get-properties", err, lager.Data{"handle": h})
			return
		default:
			selected := Select(all, r.keys)
			r.mu.Lock()
			r.properties[h] = propertyEntry{properties: selected, fetched: r.now()}
			r.mu.Unlock()
		}
	}

	r.mu.Lock()
	r.healthy = true
	r.mu.Unlock()
}

func (r *Resolver) due(handle string, now time.Time) bool {
	entry, ok := r.properties[handle]
	switch {
	case !ok:
		return true
	case entry.failed:
		return now.Sub(entry.fetched) >= retryAfterError
	default:
		return now.Sub(entry.fetched) >= r.ttl
	}
}

func (r *Resolver) gardenError(action string, err error, data lager.Data) {
	r.GardenErrors.Add(1)
	r.logger.Error(action, err, data)
	r.mu.Lock()
	r.healthy = false
	r.mu.Unlock()
}

func (r *Resolver) finish(generation uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.waited {
		if handle := r.match(name); handle != "" {
			if _, ok := r.properties[handle]; ok || len(r.keys) == 0 {
				delete(r.waited, name)
			}
		}
	}
	r.completed = generation
	close(r.refreshed)
	r.refreshed = make(chan struct{})
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
