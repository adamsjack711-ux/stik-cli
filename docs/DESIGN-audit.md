# stik-net → network auditor: design

Status: draft for review · 2026-08-21
Progress: M1 (scope + discover) ✅ · M2 (connect ports) ✅ · M3 (fingerprint) ✅ ·
M4 (audit + report) next
Author: Jack Adams-Lovell

## 1. Goal & non-goals

Turn stik-net from a **passive** L2 watcher into a tool that also runs an
**active, authorized** audit of a network: discover hosts, enumerate
services, fingerprint them, and produce a ranked findings report.

**Non-goals (v1):**
- Exploitation. This is discovery + enumeration + hygiene checks, not attack.
- Credential brute-forcing. Default-cred *detection* is a passive check
  (does the service present a known default banner / login), never a spray.
- Anything outside an explicitly authorized scope (§2).

The passive watcher stays exactly as it is; the active layer is additive and
lives behind its own commands so nothing runs a scan by accident.

## 2. Authorization is a design constraint, not a doc

The single most important design decision: **active scanning cannot start
without an explicit, on-disk scope file.** This is what keeps the tool a
pentest instrument.

- `stik-net audit` / `ports` / `discover` **refuse to run** unless given
  `--scope <file>` listing authorized CIDRs/hosts (one per line, `#` comments).
- Any target resolved during a scan that falls **outside** the scope set is
  dropped with a logged `out-of-scope` line — never probed.
- The scope file is echoed into the report header (ranges, file hash, run
  timestamp) so every report is self-documenting about what it was cleared for.
- A `--i-am-authorized` confirmation flag (or interactive y/N) on first run
  against a new scope file, recorded in the run log.

Rationale: verbal "I'm authorized" does not survive a scan hitting a host that
turns out to belong to someone else. The scope file is the artifact that makes
intent auditable.

## 3. Data model

`model.Device` is MAC-keyed and describes *passive identity*. Active results
are IP-keyed and volume-heavy, so they get their own types. Link by IP↔MAC
through the existing registry rather than bloating `Device`.

```go
// model/host.go  (new)

type Host struct {
    IP        string    `json:"ip"`
    MAC       string    `json:"mac,omitempty"`      // joined to Device when known
    Up        bool      `json:"up"`
    DiscoveredBy string `json:"discovered_by"`       // arp | tcp-ping | icmp
    Services  []Service `json:"services,omitempty"`
    ScannedAt time.Time `json:"scanned_at"`
}

type Service struct {
    Port     int    `json:"port"`
    Proto    string `json:"proto"`                   // tcp | udp
    State    string `json:"state"`                   // open | closed | filtered
    Name     string `json:"name,omitempty"`          // http, ssh, rdp…
    Product  string `json:"product,omitempty"`       // "OpenSSH", "nginx"
    Version  string `json:"version,omitempty"`
    Banner   string `json:"banner,omitempty"`        // truncated, sanitized
    TLS      *TLSInfo `json:"tls,omitempty"`
}

type Finding struct {
    ID       string   `json:"id"`                    // stik-A001
    Host     string   `json:"host"`
    Port     int      `json:"port,omitempty"`
    Severity Severity `json:"severity"`              // info|low|medium|high|critical
    Title    string   `json:"title"`
    Detail   string   `json:"detail"`
    Evidence string   `json:"evidence,omitempty"`
    Fix      string   `json:"fix,omitempty"`
}
```

`Host.MAC` is populated by joining scan results to the passive registry: if the
watcher has seen this IP's MAC, the audit report shows the friendly device name
("Jack's printer") instead of a bare IP. This is the feature that makes
stik's audit output nicer than nmap's — it already knows the devices by name.

## 4. New packages

| Package | Responsibility |
|---|---|
| `internal/probe` | Active host discovery: ARP-ping (LAN, gopacket), TCP-ping + ICMP (routed). Returns `[]Host{Up:true}`. |
| `internal/portscan` | Port scanning. Two engines behind one interface (§6). Fills `Host.Services` with state only. |
| `internal/fingerprint` | Service/version ID: banner grab, HTTP `Server`/title, TLS cert parse, a small probe table. Fills `Product/Version/TLS`. |
| `internal/audit` | Rule engine (§7) turning `[]Host` → `[]Finding`, plus report writers. |
| `internal/topo` | Infer network structure from scan + passive data (§7.5); render terminal tree + interactive HTML graph. |
| `internal/scope` | Parse + match the scope file; the gate every active package calls before touching an address. |

Existing packages reused as-is: `registry` (IP↔MAC join, device names),
`model` (extended), `notify` (report delivery), `ui` (progress), `store`
(persist scan runs).

## 5. Commands

```
stik-net discover --scope auth.txt [--passive-first]
    Host sweep only. --passive-first seeds from the watcher's known devices
    before active probing, so it's quieter.

stik-net ports <target|--scope auth.txt> [--top 1000|--ports 22,80,443|--full]
    Discover (if needed) then port-scan. Prints a live table; --json for data.

stik-net audit --scope auth.txt [--engine connect|syn] [--out report.html]
    Full pipeline: discover → ports → fingerprint → rules → topo → report.
    Refuses without --scope. Report is the HTML deliverable (§8).

stik-net topo [--from <run>|--scope auth.txt] [--out topo.html] [--ascii]
    Build/redraw the topology from the most recent scan (or run one).
    --ascii prints the tree in the terminal; default writes the HTML graph.
```

All four route addresses through `internal/scope` first. `audit` is the
headline command; `discover`/`ports`/`topo` are the composable pieces.
`topo` off `--from <run>` re-renders a *stored* scan with **no new probing**,
so redrawing the map never re-touches the network.

## 6. Scan engine: phased

Behind one `Scanner` interface so `audit` doesn't care which is active.

- **v1 — TCP connect scan.** `net.Dialer` with a worker pool. No root, fully
  portable, works today, but noisier (completes the handshake, gets logged on
  the target). Good enough to ship and to run on any box we're dropped onto.
- **v2 — SYN scan.** Raw packets via gopacket (already a dependency). Faster,
  half-open, stealthier. Needs root / `CAP_NET_RAW`. Auto-fall-back to connect
  when we lack privileges, with a logged notice — never silently.

Interface:
```go
type Scanner interface {
    Scan(ctx context.Context, host string, ports []int) ([]model.Service, error)
}
```

## 7. Severity ruleset (v1)

Rules are data-driven so they're easy to review and extend. Starting set:

- **HIGH** — remote admin exposed to a non-management range: RDP(3389),
  VNC(5900), SMB(445), Telnet(23), unauth Redis(6379)/Mongo(27017)/ES(9200).
- **MEDIUM** — plaintext admin (HTTP admin panel, FTP(21)), TLS < 1.2, expired
  or self-signed cert on a service that should be trusted, SSH allowing
  password auth (from banner/negotiation, not a login attempt).
- **LOW** — service version known-stale (small pinned table, not a live CVE
  feed in v1), verbose banners leaking version/OS.
- **INFO** — open ports that are expected/benign; inventory.

Each rule emits a `Finding` with concrete evidence (the banner line, the cert
subject) and a one-line fix — same shape as the web-audit report.

Explicitly **not** in v1: live CVE lookups (defer to a later `--cve` mode that
hits OSV/NVD), and any check that requires authenticating to the service.

## 7.5. Topology

After a scan, build a graph of the network and render it. The scan already
produced the nodes and most edges, so `topo` is mostly inference over data we
already hold — it does **not** do fresh probing unless asked to run a scan.

**Model:**
```go
// model/topo.go (new)
type Graph struct {
    Nodes []Node `json:"nodes"`
    Edges []Edge `json:"edges"`
    Roots []string `json:"roots"` // gateways / entry points
}
type Node struct {
    ID    string   `json:"id"`     // IP
    Kind  NodeKind `json:"kind"`   // gateway | host | dhcp | this-host | subnet
    Label string   `json:"label"`  // device name from registry, else IP
    Subnet string  `json:"subnet"` // CIDR it sits in
    Sev   Severity `json:"sev"`    // worst finding on the node → color
}
type Edge struct {
    From, To string  `json:"from"`
    Evidence EdgeEv  `json:"evidence"` // same-subnet | traceroute-hop | dhcp | arp
    Inferred bool    `json:"inferred"`
}
```

**Inference (each edge carries its evidence — the map is honest about what it
knows vs guesses):**

- **Gateway** = default route + DHCP server seen by the passive watcher →
  a `Roots` node, center of its subnet star.
- **Same-subnet hosts** → star edges to their gateway (`same-subnet`,
  `Inferred:true` — L3 adjacency, not proof of an L2 link).
- **Routed ranges** → one `traceroute` per reached subnet builds the router
  tree; each hop is a `traceroute-hop` edge (solid, observed).
- **DHCP / ARP** relationships from the watcher's registry annotate edges
  (`dhcp`, `arp`) — this is where the passive tool pays off: it already knows
  who hands out leases and which MAC owns which IP.
- **This host** (where stik runs) is marked so the map has a "you are here".

**Renderers (both off one `Graph`):**

- **`--ascii`** — indented tree to the terminal: gateway → subnet → hosts,
  device names, worst-severity marker per node. Zero-dependency, pipeable.
- **HTML** — a self-contained interactive graph embedded in (or beside) the
  audit report: force-directed layout on `<canvas>`, **no external libraries**
  (report must stay CSP-safe and offline). Nodes colored by worst finding
  severity, sized by open-service count; click a node → its services +
  findings. Solid edges = observed, dashed = inferred.

Node labels reuse the registry join (§3), so the map reads "Router → Jack's
NAS, Office printer, unknown 192.168.1.99" — a named picture, not an IP soup.
The topology is **inferred structure, clearly labeled as such**, never claimed
as authoritative cabling.

## 8. Reporting

Reuse the look of the web-audit report (severity scorecard → findings with
evidence → verified/observed controls). Two writers off the same `[]Finding`:

- **Terminal** — ranked table via `ui`, exit code by worst severity (CI-gate
  friendly, matches driftcheck's 0/1/2 convention).
- **HTML** — self-contained file (`--out`), scorecard + per-host findings +
  scope header. This is the client deliverable.

Device-name join (§3) means findings read "Jack's NAS · 445/tcp · SMB exposed"
not "192.168.1.20:445".

## 9. Speed (first-class, per house rule)

Every active phase is a bounded worker pool with a `--rate` cap and per-target
timeout; discovery, port scan, and fingerprint each report elapsed time. A /24
top-1000 connect scan should finish in tens of seconds, not minutes. Cache
discovery results within a run so `ports` after `discover` doesn't re-sweep.

## 10. Testing

Follow the existing discipline (real serialized fixtures, not mocks):

- `probe` — table tests against a loopback listener matrix (open/closed/filtered).
- `portscan` — spin up N `net.Listen` sockets, assert exact open-set; a
  deliberately filtered port via a dropped-SYN harness for the SYN engine.
- `scope` — the security-critical unit: exhaustive in/out-of-scope matching,
  CIDR edges, "resolved target outside scope is dropped" must have a test.
- `audit` rules — feed synthetic `[]Host` fixtures, assert exact `[]Finding`.

## 11. Increments

1. **M1 — scope + discover.** `internal/scope` (+ tests), `internal/probe`,
   `stik-net discover`. Nothing scans a port yet; the gate exists first.
2. **M2 — connect ports.** `internal/portscan` connect engine, `stik-net ports`,
   registry join for device names.
3. **M3 — fingerprint.** banners, HTTP, TLS parse.
4. **M4 — audit + report.** rule engine, terminal + HTML writers, exit codes.
5. **M5 — topo.** `internal/topo`, inference + `--ascii` tree + `<canvas>` graph
   embedded in the report; `stik-net topo --from <run>` re-renders stored scans.
6. **M6 — SYN engine.** raw-socket scanner + privilege fallback.
7. **M7 (later).** `--cve` OSV/NVD enrichment; UDP top-ports; scheduled re-audit
   that diffs against the last run (reuses the watcher's baseline idea), and a
   topo diff that highlights nodes/edges appearing or vanishing between runs.

Ship M1–M5 for a usable auditor with a map; M6+ is polish and depth.
