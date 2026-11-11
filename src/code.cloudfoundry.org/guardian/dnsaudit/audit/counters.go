package audit

import (
	"sort"
	"sync/atomic"
)

type Counters struct {
	Events             atomic.Uint64
	QueriesLogged      atomic.Uint64
	QueriesSuppressed  atomic.Uint64
	RateLimited        atomic.Uint64
	RateLimitedCell    atomic.Uint64
	Excluded           atomic.Uint64
	Malformed          atomic.Uint64
	Unsupported        atomic.Uint64
	NotQuery           atomic.Uint64
	ResponsesMatched   atomic.Uint64
	ResponsesUnmatched atomic.Uint64
	ResponsesTimedOut  atomic.Uint64
	PendingFull        atomic.Uint64
	DedupCacheFull     atomic.Uint64
}

func (c *Counters) Values() map[string]uint64 {
	return map[string]uint64{
		"events":              c.Events.Load(),
		"queries_logged":      c.QueriesLogged.Load(),
		"queries_suppressed":  c.QueriesSuppressed.Load(),
		"rate_limited":        c.RateLimited.Load(),
		"rate_limited_cell":   c.RateLimitedCell.Load(),
		"excluded":            c.Excluded.Load(),
		"malformed":           c.Malformed.Load(),
		"unsupported":         c.Unsupported.Load(),
		"not_query":           c.NotQuery.Load(),
		"responses_matched":   c.ResponsesMatched.Load(),
		"responses_unmatched": c.ResponsesUnmatched.Load(),
		"responses_timed_out": c.ResponsesTimedOut.Load(),
		"pending_full":        c.PendingFull.Load(),
		"dedup_cache_full":    c.DedupCacheFull.Load(),
	}
}

func SortedNames(values map[string]uint64) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
