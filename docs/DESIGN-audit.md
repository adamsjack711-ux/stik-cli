# stik-net → network auditor: design

Status: draft for review · 2026-08-21
Progress: M1 (scope + discover) ✅ · M2 (connect ports) ✅ · M3 (fingerprint) ✅ ·
M4 (audit + report) ✅ · M5 (topology) ✅ · M6 (SYN engine) ✅ ·
M7 re-audit diff ✅ · topo diff ✅ · UDP ✅ · --cve ✅ — M1–M7 complete
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

**How M6 built it:**

- **Send and receive use different mechanisms, deliberately.** SYNs go out on an
  `ip4:tcp` raw socket, so the kernel writes the IP header and we skip ARP and
  L2 entirely. Replies come back through pcap with a tight BPF filter, because
  BSD-derived kernels (macOS included) never deliver TCP to a raw socket. One
  mechanism would have been neater; two is what actually works on both targets.
- **The kernel sends the RST.** The SYN/ACK arrives at a port no socket is bound
  to, so the host's own stack tears the half-open connection down. That is how
  every SYN scanner behaves, and it is worth stating rather than discovering.
- **`filtered` finally means something.** On the connect engine, filtered is
  "a dial error we couldn't interpret". Here it is an observation: the SYN went
  out, one retransmit followed, and nothing came back.
- **Engine choice is a value, not a side effect.** `EngineChoice` resolves a
  name into a Scanner and reports what it settled on, so the fallback to connect
  can be printed, tested, and reasoned about. The engines leave different traces
  on the target — an operator who thinks they ran half-open when they didn't has
  been misled about what the target logged.
- **`ScanHosts` grew a second shape.** The connect engine keeps the flat
  host:port fan-out it is fastest with; the SYN engine gets a per-host path,
  because it holds one capture handle and one source port per target. The scope
  gate is applied identically on both paths.
- **Coverage limit, stated plainly.** Packet construction, flag classification,
  the BPF filter, silence-means-filtered, and every branch of the engine
  fallback are unit-tested. The live scan needs root, so it is a test that skips
  unless `os.Geteuid() == 0` — unprivileged CI never runs it.
- **The dropped-SYN harness (§10) now exists.** The obvious way to arrange a
  filtered port is a firewall rule, which means mutating the firewall of
  whatever machine runs the tests and restoring it correctly afterwards —
  including when a test panics. Instead the harness saturates a listening
  socket's accept queue: past the backlog the kernel drops SYNs on the floor.
  No SYN/ACK, no RST, and the host is unquestionably alive — which is the part
  the black-hole test cannot show, since an address that routes nowhere is a
  different situation from a host that answers on one port and drops another.
  Nothing is mutated, so there is nothing to restore.
  The harness **verifies its own premise** before asserting: queue behaviour
  differs between kernels, so if this machine refuses or accepts instead of
  dropping, the test skips and says which — a test that cannot fail is worse
  than no test. The connect half runs unprivileged, so filtered is finally
  covered in CI; the SYN half is root-gated like its siblings.

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

**Where the shipped ruleset departs from this plan (M4):**

- **Self-signed certs are LOW, not MEDIUM.** On the home and lab networks this
  tool is pointed at, every NAS, printer and router is self-signed; at MEDIUM
  the finding is noise that trains the reader to skim. Expired certs stay
  MEDIUM, and the two are mutually exclusive so a stale appliance cert produces
  one finding, not two.
- **No INFO findings.** The design used INFO as inventory; the report carries a
  real inventory section instead ("what's reachable"), which says the same thing
  without diluting the findings list.
- **"Unauth Redis/Mongo/ES" ships as "reachable", not "unauthenticated".**
  Proving a datastore is unauthenticated means issuing a command to it, which is
  a §1 non-goal. The rule reports exposure and says plainly what it did and
  didn't check.
- **Exit codes** are 0 clean / 1 at-or-above `--fail-on` (default `high`) /
  2 the run itself failed, so a broken scope file can never be read by a
  pipeline as a clean scan.

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

**What M5 actually shipped, and what it didn't:**

- **No traceroute.** The design called for one traceroute per routed subnet to
  build a router tree. It isn't here: traceroute needs raw sockets (root) and
  the networks this tool is aimed at are single-subnet, where it is a no-op. The
  edge kinds are in the model, so adding `traceroute-hop` later changes the
  inference, not the renderers. Until then the map draws subnet stars, and says
  which links it reasoned rather than watched.
- **Gateways are found two ways, and the map distinguishes them.** A host the
  passive watcher saw handing out DHCP leases is an *observed* gateway (solid
  edge). Otherwise the `.1` convention is used as a fallback and drawn dashed —
  a guess that is labelled a guess ("gateway · assumed" in the tree).
- **The graph is persisted with the run.** `topo --from <run>` re-renders the
  stored graph rather than re-inferring it, which is what makes redrawing
  provably probe-free: the command never touches the probe, scan, or fingerprint
  packages at all. Runs live in `~/.stik/runs/`, written atomically.
- **The canvas graph has no test for its rendering.** Go tests cover the
  inference, the ASCII tree, escaping, and self-containment; a `node --check`
  test (skipped when node is absent) stops a syntax error shipping. Actual
  layout and click behaviour in a browser is unverified by CI.

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
  (Shipped: the harness fills a listen backlog rather than touching a firewall,
  and skips rather than passing if a kernel does not drop past a full queue.)
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

**M7, part one — the re-audit diff (shipped):**

`stik-net diff` compares two saved runs and `stik-net audit --diff` compares the
run it just finished with the previous one. Both scan nothing: the runs are
already on disk. This is the auditor's version of what the passive watcher does
with devices — the last run is the baseline, and what matters is what changed.

- **Keys.** Hosts by IP, services by host+port, findings by rule+host+port. A
  finding re-observed on the same port is continuity, not news.
- **The severity gate counts only what appeared.** `--fail-on` looks at new
  findings alone, so a known high finding cannot fail a change gate every night,
  and fixing something can never look like a regression.
- **One event, reported once.** A host that vanished is one line, not one line
  per port it used to have open.
- **Bug this shook out:** runs were named to the second, so two audits inside
  one second silently overwrote each other — which would have destroyed the
  baseline a diff compares against and made the next diff report "nothing
  changed" against itself. `SaveRun` now suffixes on collision.
**M7, part four — `--cve` (shipped):**

This is the only part of stik-net that contacts the internet, and the tension is
real: everything else works on a network it does not trust. The OUI table is
embedded rather than fetched, reports pull in no remote assets, and the passive
watcher transmits nothing at all. So the rules are:

- **Opt-in, and it says what it sends.** `--cve` prints, before querying, that
  product and version names — not addresses, not host names — are going to NIST.
  Someone auditing a network they were lent should not discover that afterwards.
- **Cached for a week, on disk.** The first reason is disclosure, not rate
  limits: a nightly re-audit of an unchanged network should tell a third party
  nothing new. A test asserts the second run makes no request.
- **Only fully identified services are looked up.** Product *and* version, and
  only products in a small hand-checked CPE table. A wrong mapping does not
  produce no answer — it produces confident wrong answers about somebody else's
  software.
- **Findings cap at high, never critical.** A CVE matched on version alone is a
  lead to verify: the host may already carry a distro backport. The finding says
  so in as many words.
- **Grouped queries.** Ten identical nginx boxes cost one lookup — fewer
  requests, and less disclosed about the shape of the network.
- **NVD being down is not fatal.** Errors are collected and printed; a scan that
  found real exposure is not thrown away because a third party was unreachable.
- **Tested against a real response**, captured from the live API and committed
  as a fixture. A stub only proves the parser agrees with my idea of the schema.

**M7, part three — UDP (shipped):**

UDP is a different problem from TCP, and pretending otherwise is how scanners
produce confident nonsense.

- **Three states, not two.** `open` when something answered, `closed` on ICMP
  port unreachable, and **`open|filtered`** for silence — because a service with
  nothing to say to our probe is indistinguishable from a dropped packet.
  Reporting either "open" or "filtered" there would be a guess dressed as a
  result. No rule fires on `open|filtered` for the same reason.
- **Unprivileged.** A *connected* UDP socket surfaces the ICMP unreachable as
  `ECONNREFUSED`, so closed detection needs no raw socket and no root.
- **Real payloads.** An empty datagram gets nothing back from a resolver or an
  NTP server, so each known port gets the smallest well-formed request that
  protocol answers (DNS `version.bind`, NTP mode 3, SSDP M-SEARCH, NetBIOS node
  status, mDNS service enumeration, TFTP read, IPMI presence ping).
- **Two lines this stays behind.** Every payload is a read or a presence check —
  nothing asks a service to *do* anything. And 67/68 get the generic probe
  rather than a real DHCPDISCOVER: requesting a lease takes an address off the
  network, which is a change, not an observation. A test pins that.
- **SNMP uses the default community "public",** which is default-credential
  *detection* as §1 allows (one request, never a spray). An agent that answers
  is itself the finding.
- **Short port list on purpose.** UDP has no handshake, so every silent port
  costs a full timeout. A useful sweep is a dozen ports, not a thousand.

**M7, part two — the topo diff (shipped):**

`stik-net diff --map` marks the tree and `--out` writes a highlighted map. The
result is the **union of both runs as one graph**, with each node and edge
marked added / removed / worse / better, so the existing renderers draw it and
no second layout exists to drift out of sync. A removed host is carried over
from the earlier map, because the picture should still show where it used to
sit. Change markers live on `model.Node`, empty on an ordinary map, so nothing
about a normal render shifts.

- **A subnet's severity is a roll-up, so it is coloured but never counted.**
  One host getting worse drags its subnet up with it; counting both would report
  one event twice. A test pins this.

Ship M1–M5 for a usable auditor with a map; M6+ is polish and depth.
