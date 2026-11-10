package audit

import (
	"time"

	"code.cloudfoundry.org/guardian/dnsaudit/decode"
	"code.cloudfoundry.org/guardian/dnsaudit/identity"
	"code.cloudfoundry.org/lager/v3"
)

type Direction uint8

const (
	Egress  Direction = 0
	Ingress Direction = 1
)

type Event struct {
	CgroupID  uint64
	Time      time.Time
	Direction Direction
	Data      []byte
}

//go:generate counterfeiter -o fakes/resolver.go --fake-name Resolver . Resolver
type Resolver interface {
	Resolve(cgroupID uint64) (identity.Container, bool)
}

type Host struct {
	IP string `json:"ip"`
	ID string `json:"id"`
}

type Query struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	ID       uint16 `json:"id"`
	Protocol string `json:"protocol"`
	Family   string `json:"family"`
	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint16 `json:"dst_port"`
	Time     string `json:"time"`
}

type Response struct {
	Received bool   `json:"received"`
	RCode    string `json:"rcode,omitempty"`
}

type Options struct {
	DedupWindow       time.Duration
	RatePerSecond     int
	Burst             int
	CellRatePerSecond int
	CellBurst         int
	ExcludeDomains    []string
	CaptureResponses  bool
	ResponseTimeout   time.Duration
	MaxDedupBytes     int
	MaxPending        int
	MaxSuffixes       int
	TopSuffixes       int
	Host              Host
}

type pendingKey struct {
	handle string
	id     uint16
	port   uint16
	name   string
	qtype  string
}

type pendingQuery struct {
	key       pendingKey
	container identity.Container
	query     Query
	repeats   uint64
	captured  time.Time
}

// Processor turns captured packets into log lines. It is not safe for
// concurrent use; call Handle and Tick from one goroutine.
type Processor struct {
	opts     Options
	resolver Resolver
	logger   lager.Logger
	now      func() time.Time
	Counters *Counters

	excluder  *Excluder
	deduper   *Deduper
	limiter   *RateLimiter
	pending   map[pendingKey]*pendingQuery
	order     []*pendingQuery
	lastPrune time.Time
}

func NewProcessor(opts Options, resolver Resolver, logger lager.Logger, now func() time.Time) *Processor {
	return &Processor{
		opts:      opts,
		resolver:  resolver,
		logger:    logger,
		now:       now,
		Counters:  &Counters{},
		excluder:  NewExcluder(opts.ExcludeDomains),
		deduper:   NewDeduper(opts.DedupWindow, opts.MaxDedupBytes),
		limiter:   NewRateLimiter(opts.RatePerSecond, opts.Burst, opts.CellRatePerSecond, opts.CellBurst, opts.MaxSuffixes, opts.TopSuffixes),
		pending:   map[pendingKey]*pendingQuery{},
		lastPrune: now(),
	}
}

func (p *Processor) Handle(ev Event) {
	p.Counters.Events.Add(1)

	msg, reason := decode.Decode(ev.Data)
	switch reason {
	case decode.ReasonOK:
	case decode.ReasonIgnored:
		return
	case decode.ReasonMalformed:
		p.Counters.Malformed.Add(1)
		return
	case decode.ReasonUnsupported:
		p.Counters.Unsupported.Add(1)
		return
	default:
		p.Counters.NotQuery.Add(1)
		return
	}

	if ev.Direction == Egress {
		if msg.Response {
			p.Counters.NotQuery.Add(1)
			return
		}
		p.handleQuery(ev, msg)
		return
	}
	if msg.Response {
		p.handleResponse(ev, msg)
	}
}

func (p *Processor) handleQuery(ev Event, msg decode.Message) {
	container, ok := p.resolver.Resolve(ev.CgroupID)
	if !ok {
		return
	}
	if p.excluder.Excluded(msg.Name) {
		p.Counters.Excluded.Add(1)
		return
	}

	now := p.now()
	log, repeats, full := p.deduper.Check(container, msg.Name, msg.Type, now)
	if full {
		p.Counters.DedupCacheFull.Add(1)
	}
	if !log {
		p.Counters.QueriesSuppressed.Add(1)
		return
	}
	if allowed, byCell := p.limiter.Allow(container, msg.Name, now); !allowed {
		p.Counters.RateLimited.Add(1)
		if byCell {
			p.Counters.RateLimitedCell.Add(1)
		}
		return
	}
	p.deduper.Logged(container, msg.Name, msg.Type, now)

	query := Query{
		Name:     msg.Name,
		Type:     msg.Type,
		ID:       msg.ID,
		Protocol: msg.Protocol,
		Family:   msg.Family,
		SrcIP:    msg.SrcIP,
		SrcPort:  msg.SrcPort,
		DstIP:    msg.DstIP,
		DstPort:  msg.DstPort,
		Time:     ev.Time.UTC().Format(time.RFC3339Nano),
	}

	if !p.opts.CaptureResponses {
		p.emitQuery(container, query, repeats, nil)
		return
	}

	key := pendingKey{handle: container.Handle, id: msg.ID, port: msg.SrcPort, name: msg.Name, qtype: msg.Type}
	if previous, ok := p.pending[key]; ok {
		delete(p.pending, key)
		p.Counters.ResponsesTimedOut.Add(1)
		p.emitQuery(previous.container, previous.query, previous.repeats, &Response{Received: false})
	}
	if len(p.pending) >= p.opts.MaxPending {
		p.Counters.PendingFull.Add(1)
		p.emitQuery(container, query, repeats, &Response{Received: false})
		return
	}
	pq := &pendingQuery{key: key, container: container, query: query, repeats: repeats, captured: now}
	p.pending[key] = pq
	p.order = append(p.order, pq)
}

func (p *Processor) handleResponse(ev Event, msg decode.Message) {
	container, ok := p.resolver.Resolve(ev.CgroupID)
	if !ok {
		return
	}
	key := pendingKey{handle: container.Handle, id: msg.ID, port: msg.DstPort, name: msg.Name, qtype: msg.Type}
	pq, ok := p.pending[key]
	if !ok {
		p.Counters.ResponsesUnmatched.Add(1)
		return
	}
	delete(p.pending, key)
	p.Counters.ResponsesMatched.Add(1)
	p.emitQuery(pq.container, pq.query, pq.repeats, &Response{Received: true, RCode: msg.RCode})
}

// Tick logs queries whose response did not arrive in time and, once per dedup
// window, the summaries of suppressed and rate-limited queries.
func (p *Processor) Tick() {
	now := p.now()
	for len(p.order) > 0 {
		pq := p.order[0]
		if p.pending[pq.key] != pq {
			p.order = p.order[1:]
			continue
		}
		if now.Sub(pq.captured) < p.opts.ResponseTimeout {
			break
		}
		p.order = p.order[1:]
		delete(p.pending, pq.key)
		p.Counters.ResponsesTimedOut.Add(1)
		p.emitQuery(pq.container, pq.query, pq.repeats, &Response{Received: false})
	}
	if len(p.order) == 0 {
		p.order = nil
	}

	if now.Sub(p.lastPrune) >= p.opts.DedupWindow {
		p.summarise(now)
	}
}

// Flush logs everything still held, for example before shutting down.
func (p *Processor) Flush() {
	for _, pq := range p.order {
		if p.pending[pq.key] == pq {
			p.emitQuery(pq.container, pq.query, pq.repeats, &Response{Received: false})
		}
	}
	p.pending = map[pendingKey]*pendingQuery{}
	p.order = nil
	p.summarise(p.now().Add(p.opts.DedupWindow))
}

func (p *Processor) summarise(now time.Time) {
	p.lastPrune = now
	for _, r := range p.deduper.Prune(now) {
		p.logger.Info("dns-repeats", lager.Data{
			"container":          r.Container,
			"host":               p.opts.Host,
			"query":              map[string]string{"name": r.Name, "type": r.Type},
			"repeats_suppressed": r.Suppressed,
		})
	}
	for _, d := range p.limiter.Drain() {
		data := lager.Data{
			"container":    d.Container,
			"host":         p.opts.Host,
			"dropped":      d.Dropped,
			"top_suffixes": d.TopSuffixes,
		}
		if d.DroppedByCellLimit > 0 {
			data["dropped_by_cell_limit"] = d.DroppedByCellLimit
		}
		p.logger.Info("dns-rate-limited", data)
	}
	p.limiter.Prune(now)
}

func (p *Processor) emitQuery(container identity.Container, query Query, repeats uint64, response *Response) {
	data := lager.Data{
		"container":          container,
		"host":               p.opts.Host,
		"query":              query,
		"repeats_suppressed": repeats,
	}
	if response != nil {
		data["response"] = response
	}
	p.logger.Info("dns-query", data)
	p.Counters.QueriesLogged.Add(1)
}

func (p *Processor) PendingLen() int { return len(p.pending) }
