---
title: DNS Audit
expires_at: never
tags: [ garden-runc-release ]
---

# DNS Audit

The optional `dns-audit` job records DNS questions sent in plain text by
containers, attributed to the container that sent them and to selected
container properties, for example the Cloud Foundry app, space and org. It
helps operators investigate lookups that are not followed by a connection,
such as lookups that fail or that carry data themselves.

## How it works

- Two small eBPF programs of type `cgroup_skb`, built in Go at start-up, are attached to Garden's parent
  cgroup (`/sys/fs/cgroup/garden`) through BPF links:
  - the egress program sees packets sent by sockets in any container cgroup
    and copies DNS queries (UDP or TCP to port 53, IPv4 or IPv6) into a ring
    buffer;
  - the optional ingress program does the same for DNS responses, to record
    the response code.
- Both programs always let the packet through. They never delay, drop or
  change traffic.
- A userspace daemon reads the ring buffer, maps the cgroup of the sending
  socket to the Garden container handle, reads the configured container
  properties from the Garden API, and writes one JSON line per query to
  `/var/vcap/sys/log/dns-audit/dns.log`.
- Attribution comes from the kernel (the socket's cgroup), not from IP
  addresses, so it is correct even when a container forges its source address
  or an IP address is reused.
- When the daemon stops or crashes, its BPF links are closed and the programs
  are detached.

Requirements: cgroups v2 (Noble stemcells) and the `garden` job on the same
instance.

## Enabling

Add the `dns-audit` job to the instance group that runs `garden` and set
`dns_audit.enabled: true`. For Cloud Foundry apps, a useful property list is:

```yaml
- name: dns-audit
  release: garden-runc
  properties:
    dns_audit:
      enabled: true
      capture_responses: true
      properties:
        - network.app_id
        - network.space_id
        - network.org_id
        - app_name
        - space_name
        - organization_name
        - process_type
        - instance_id
```

Each key is looked up as a Garden container property first and then as a tag
of the `log_config` property, which the Diego executor sets from the metric
tags of the app.

DNS query names can be sensitive. Check your data protection requirements
before enabling this job, forward `dns.log` only to a log store with
restricted access, and don't forward it to app log streams.

## Log lines

- `garden.dns-audit.dns-query`: one line per query.
- `garden.dns-audit.dns-repeats`: identical queries that were suppressed and
  not reported with a later query.
- `garden.dns-audit.dns-rate-limited`: queries dropped by the per-container
  rate limit, with the most frequent domain suffixes (last two labels).

Query names are lowercased and written like `dig` prints them: a dot inside a
label is `\.`, a backslash is `\\`, and other bytes outside printable ASCII are
`\DDD` (decimal).

Example query line (with `capture_responses: true`):

```json
{
  "timestamp": "2026-11-05T10:15:02.130971311Z",
  "level": "info",
  "source": "garden.dns-audit",
  "message": "garden.dns-audit.dns-query",
  "data": {
    "container": {
      "handle": "5f0c2a6e-1b7d-4c8e-6a91-3d2e",
      "cgroup": "5f0c2a6e-1b7d-4c8e-6a91-3d2e/init",
      "properties": {
        "app_name": "my-app",
        "instance_id": "0",
        "network.app_id": "3b8e5d2a-6c41-4f0e-9a7d-2c5b8e1f4a60",
        "network.org_id": "9d2f4e6a-8b13-4c5d-a7e9-1f3b5d7c9e20",
        "network.space_id": "6e1a3c5b-7d92-4f8a-b4c6-8a0d2e4f6b13",
        "organization_name": "my-org",
        "process_type": "web",
        "space_name": "my-space"
      }
    },
    "host": { "ip": "10.0.16.20", "id": "b7c9d1e3-f5a7-4b9c-8d1e-3f5a7b9c1d2e" },
    "query": {
      "name": "example.com",
      "type": "A",
      "id": 32789,
      "protocol": "udp",
      "family": "ipv4",
      "src_ip": "10.255.17.50",
      "src_port": 54990,
      "dst_ip": "169.254.0.53",
      "dst_port": 53,
      "time": "2026-11-05T10:15:02.123705207Z"
    },
    "repeats_suppressed": 0,
    "response": { "received": true, "rcode": "NXDOMAIN" }
  }
}
```

`container.cgroup` shows which process group sent the query, for example
`<handle>/init` for the app, `<handle>/<handle>-envoy` for the proxy, or
`<handle>-liveness-healthcheck-0` for a health check. `query.time` is the time
the packet was captured; `response.received` is `false` when no response
arrived within the timeout.

## Volume controls

| Property | Default | Effect |
|---|---|---|
| `dns_audit.dedup_window_seconds` | `60` | Identical queries per container within the window are counted, not logged |
| `dns_audit.max_logs_per_second_per_container` | `10` | Per-container limit, with bursts of five times the limit; excess is summarised |
| `dns_audit.exclude_domains` | `[]` | Suffixes never logged. Only exclude zones answered on the cell, such as platform-internal domains; zones forwarded to outside resolvers can carry data |
| `dns_audit.ring_buffer_size_kb` | `4096` | Kernel buffer between the programs and the daemon |

Dropped or suppressed queries are always reported in summary lines.

## Metrics

The daemon writes a `dns-audit.metrics` line with these counters to its own
log (`/var/vcap/sys/log/dns-audit/dns-audit.stdout.log`) every 30 seconds:

| Metric | Meaning |
|---|---|
| `kernel_events` | Packets copied by the eBPF programs |
| `ringbuf_full` | Packets not copied because the ring buffer was full |
| `events` | Packets processed by the daemon |
| `queries_logged`, `queries_suppressed`, `rate_limited`, `excluded` | Volume controls |
| `responses_matched`, `responses_unmatched`, `responses_timed_out`, `pending_responses` | Response capture |
| `malformed`, `unsupported`, `not_query` | Packets to or from port 53 that couldn't be used |
| `unknown_cgroups` | Packets from cgroups that couldn't be mapped to a container |
| `garden_errors` | Failed Garden API requests; lines are then written with the handle only |
| `dedup_cache_full`, `pending_full` | Memory limits reached |

## Limitations

The following are not recorded:

- encrypted DNS (DNS over HTTPS, TLS or QUIC) and DNS on ports other than 53;
- packets sent through raw packet sockets (`AF_PACKET`) inside a container;
- DNS over TCP when the 2-byte length prefix and the message are sent in
  separate segments;
- IPv6 packets with extension headers;
- privileged containers, which don't run in Garden's cgroup tree;
- cells with cgroups v1.

When a query contains several questions, only the first is recorded.

## The eBPF programs

The programs are built at start-up with the `asm` package of
[cilium/ebpf](https://github.com/cilium/ebpf), in
`src/code.cloudfoundry.org/guardian/dnsaudit/bpf/program.go`: there is no C source,
no compiled object and no clang build step. They only use helpers that are not
restricted to GPL-licensed programs and carry the licence string `Apache-2.0`.
