package audit

import (
	"sort"
	"strings"
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/decode"
	"code.cloudfoundry.org/guardian/dnsaudit/identity"
)

type Excluder struct {
	suffixes []string
}

func NewExcluder(suffixes []string) *Excluder {
	e := &Excluder{}
	for _, s := range suffixes {
		s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
		if s != "" {
			e.suffixes = append(e.suffixes, s)
		}
	}
	return e
}

// Excluded reports whether name equals one of the suffixes or ends with one of
// them on a label boundary. Names are escaped, so a dot preceded by an odd
// number of backslashes is part of a label.
func (e *Excluder) Excluded(name string) bool {
	for _, s := range e.suffixes {
		if name == s {
			return true
		}
		if len(name) > len(s) && strings.HasSuffix(name, s) {
			dot := len(name) - len(s) - 1
			if name[dot] == '.' && !decode.Escaped(name, dot) {
				return true
			}
		}
	}
	return false
}

type dedupKey struct {
	handle string
	name   string
	qtype  string
}

type dedupEntry struct {
	container  identity.Container
	lastLogged time.Time
	lastSeen   time.Time
	suppressed uint64
}

type Repeats struct {
	Container  identity.Container
	Name       string
	Type       string
	Suppressed uint64
}

// Deduper tracks identical queries (container, name, type). Its memory is
// bounded by an estimate of the bytes held per entry.
type Deduper struct {
	window   time.Duration
	maxBytes int
	bytes    int
	entries  map[dedupKey]*dedupEntry
}

const dedupEntryOverhead = 128

func NewDeduper(window time.Duration, maxBytes int) *Deduper {
	return &Deduper{window: window, maxBytes: maxBytes, entries: map[dedupKey]*dedupEntry{}}
}

func entrySize(key dedupKey) int {
	return len(key.handle) + len(key.name) + len(key.qtype) + dedupEntryOverhead
}

// Check reports whether a query should be logged and, if so, how many
// identical queries were suppressed since it was last logged, and whether the
// cache is full so the query can't be tracked. A query inside the window is
// counted as a repeat. Call Logged once the query has actually been logged.
func (d *Deduper) Check(container identity.Container, name, qtype string, now time.Time) (bool, uint64, bool) {
	key := dedupKey{handle: container.Handle, name: name, qtype: qtype}
	if entry, ok := d.entries[key]; ok {
		entry.lastSeen = now
		if now.Sub(entry.lastLogged) < d.window {
			entry.suppressed++
			return false, 0, false
		}
		return true, entry.suppressed, false
	}
	return true, 0, d.bytes+entrySize(key) > d.maxBytes
}

// Logged starts a new window for a query that was logged, unless the cache
// is full.
func (d *Deduper) Logged(container identity.Container, name, qtype string, now time.Time) {
	key := dedupKey{handle: container.Handle, name: name, qtype: qtype}
	if entry, ok := d.entries[key]; ok {
		entry.suppressed = 0
		entry.lastLogged = now
		entry.lastSeen = now
		entry.container = container
		return
	}
	size := entrySize(key)
	if d.bytes+size > d.maxBytes {
		return
	}
	d.entries[key] = &dedupEntry{container: container, lastLogged: now, lastSeen: now}
	d.bytes += size
}

// Prune forgets queries not seen for a full window and returns the ones that
// still had suppressed repeats, so their counts can be reported.
func (d *Deduper) Prune(now time.Time) []Repeats {
	var flushed []Repeats
	for key, entry := range d.entries {
		if now.Sub(entry.lastSeen) < d.window {
			continue
		}
		if entry.suppressed > 0 {
			flushed = append(flushed, Repeats{
				Container:  entry.container,
				Name:       key.name,
				Type:       key.qtype,
				Suppressed: entry.suppressed,
			})
		}
		delete(d.entries, key)
		d.bytes -= entrySize(key)
	}
	sort.Slice(flushed, func(i, j int) bool {
		if flushed[i].Container.Handle != flushed[j].Container.Handle {
			return flushed[i].Container.Handle < flushed[j].Container.Handle
		}
		return flushed[i].Name < flushed[j].Name
	})
	return flushed
}

func (d *Deduper) Len() int   { return len(d.entries) }
func (d *Deduper) Bytes() int { return d.bytes }

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
}

type SuffixCount struct {
	Suffix string `json:"suffix"`
	Count  uint64 `json:"count"`
}

type Dropped struct {
	Container identity.Container
	Dropped   uint64
	// DroppedByCellLimit is the part of Dropped that the container's own limit
	// would have allowed.
	DroppedByCellLimit uint64
	TopSuffixes        []SuffixCount
}

type dropState struct {
	container identity.Container
	dropped   uint64
	byCell    uint64
	suffixes  map[string]uint64
}

// RateLimiter is a token bucket per container plus one for the whole cell.
// It remembers what it dropped, per container and name suffix, so that the
// summary still shows where the queries went.
type RateLimiter struct {
	rate        float64
	burst       float64
	cellRate    float64
	cellBurst   float64
	maxSuffixes int
	topSuffixes int
	cell        *bucket
	buckets     map[string]*bucket
	dropped     map[string]*dropState
}

const otherSuffixes = "(other)"

// NewRateLimiter returns a limiter that allows perSecond queries per container
// with bursts of burst, and cellPerSecond queries for all containers together
// with bursts of cellBurst. A cellPerSecond of 0 disables the cell limit.
func NewRateLimiter(perSecond, burst, cellPerSecond, cellBurst, maxSuffixes, topSuffixes int) *RateLimiter {
	return &RateLimiter{
		rate:        float64(perSecond),
		burst:       float64(burst),
		cellRate:    float64(cellPerSecond),
		cellBurst:   float64(cellBurst),
		maxSuffixes: maxSuffixes,
		topSuffixes: topSuffixes,
		buckets:     map[string]*bucket{},
		dropped:     map[string]*dropState{},
	}
}

// Allow reports whether a query may be logged and, if not, whether it was
// the cell limit that dropped it. A query dropped by the cell limit doesn't
// use up the container's own allowance.
func (r *RateLimiter) Allow(container identity.Container, name string, now time.Time) (bool, bool) {
	b, ok := r.buckets[container.Handle]
	if !ok {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[container.Handle] = b
	}
	b.refill(now, r.rate, r.burst)
	if b.tokens < 1 {
		r.drop(container, name, false)
		return false, false
	}

	if r.cellRate > 0 {
		if r.cell == nil {
			r.cell = &bucket{tokens: r.cellBurst, last: now}
		}
		r.cell.refill(now, r.cellRate, r.cellBurst)
		if r.cell.tokens < 1 {
			r.drop(container, name, true)
			return false, true
		}
		r.cell.tokens--
	}
	b.tokens--
	return true, false
}

func (r *RateLimiter) drop(container identity.Container, name string, byCell bool) {
	state, ok := r.dropped[container.Handle]
	if !ok {
		state = &dropState{suffixes: map[string]uint64{}}
		r.dropped[container.Handle] = state
	}
	state.container = container
	state.dropped++
	if byCell {
		state.byCell++
	}
	suffix := decode.Suffix(name)
	if _, tracked := state.suffixes[suffix]; !tracked && len(state.suffixes) >= r.maxSuffixes {
		suffix = otherSuffixes
	}
	state.suffixes[suffix]++
}

// Drain returns what was dropped since the previous call, per container.
func (r *RateLimiter) Drain() []Dropped {
	var out []Dropped
	for _, state := range r.dropped {
		counts := make([]SuffixCount, 0, len(state.suffixes))
		for suffix, count := range state.suffixes {
			counts = append(counts, SuffixCount{Suffix: suffix, Count: count})
		}
		sort.Slice(counts, func(i, j int) bool {
			if counts[i].Count != counts[j].Count {
				return counts[i].Count > counts[j].Count
			}
			return counts[i].Suffix < counts[j].Suffix
		})
		if len(counts) > r.topSuffixes {
			counts = counts[:r.topSuffixes]
		}
		out = append(out, Dropped{Container: state.container, Dropped: state.dropped, DroppedByCellLimit: state.byCell, TopSuffixes: counts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Container.Handle < out[j].Container.Handle })
	r.dropped = map[string]*dropState{}
	return out
}

// Prune forgets buckets that have refilled completely.
func (r *RateLimiter) Prune(now time.Time) {
	for key, b := range r.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*r.rate >= r.burst {
			delete(r.buckets, key)
		}
	}
}

func (r *RateLimiter) Len() int { return len(r.buckets) }
