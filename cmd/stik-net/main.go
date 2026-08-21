// Command stik-net is a passive network watcher. nmap tells you what's on your
// network right now; stik-net remembers what's normal and tells you when that
// changes. It listens only to broadcast/multicast traffic (ARP, mDNS, DHCP),
// never transmits, and is meant for networks you own.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// exitCode is an error that carries a process exit status instead of a message.
// `audit` uses it to signal "the run worked, and what it found is bad enough to
// fail a pipeline" — distinct from an error, which is always 2.
type exitCode int

func (c exitCode) Error() string { return "exit status " + strconv.Itoa(int(c)) }

// codedError is an error that still gets reported, but with a chosen exit
// status. audit uses it so a broken scope file (2) can't be mistaken by a
// pipeline for a scan that found something (1).
type codedError struct {
	code int
	err  error
}

func (c codedError) Error() string { return c.err.Error() }
func (c codedError) Unwrap() error { return c.err }

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	verbose := false
	var positional []string
	var notifySpecs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--verbose" || a == "-v":
			verbose = true
		case a == "--help" || a == "-h" || a == "help":
			fmt.Print(helpText)
			return 0
		case a == "--version" || a == "-V" || a == "version":
			fmt.Println("stik-net " + version)
			return 0
		case a == "--notify":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "stik-net: --notify needs a value (desktop, ntfy://…, or an http(s) URL)")
				return 2
			}
			notifySpecs = append(notifySpecs, args[i+1])
			i++
		case strings.HasPrefix(a, "--notify="):
			notifySpecs = append(notifySpecs, strings.TrimPrefix(a, "--notify="))
		default:
			positional = append(positional, a)
		}
	}

	a := newApp()

	var cmd string
	var rest []string
	if len(positional) > 0 {
		cmd, rest = positional[0], positional[1:]
	}

	var err error
	switch cmd {
	case "":
		err = a.cmdStatus()
	case "devices", "list":
		err = a.cmdDevices(verbose)
	case "watch":
		err = a.cmdWatch()
	case "discover":
		err = a.cmdDiscover(rest)
	case "ports":
		err = a.cmdPorts(rest)
	case "audit":
		err = a.cmdAudit(rest)
	case "topo", "map":
		err = a.cmdTopo(rest)
	case "diff":
		err = a.cmdDiff(rest)
	case "daemon":
		err = a.cmdDaemon(notifySpecs)
	case "service":
		err = a.cmdService(rest, notifySpecs)
	case "name":
		err = a.cmdName(rest)
	case "forget":
		err = a.cmdForget(rest)
	default:
		fmt.Fprintf(os.Stderr, "stik-net: unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, helpText)
		return 2
	}

	if err != nil {
		var code exitCode
		if errors.As(err, &code) {
			return int(code) // already reported by the command itself
		}
		status := 1
		var coded codedError
		if errors.As(err, &coded) {
			status = coded.code
		}
		if msg, ok := friendlyError(a.style, err); ok {
			fmt.Fprintln(os.Stderr, msg)
			return status
		}
		fmt.Fprintln(os.Stderr, "stik-net: "+err.Error())
		return status
	}
	return 0
}

const helpText = `stik-net — a passive watcher that tells you what's on your network,
and taps you on the shoulder when something new shows up.

Usage:
  stik-net              status: is anything new? (runs the setup wizard on first use)
  stik-net devices      list every device in plain terms (--verbose for MACs & details)
  stik-net watch        live view; new devices highlight as they appear
  stik-net discover     active host sweep of an authorized scope (needs --scope)
  stik-net ports [tgt]  connect-scan open ports and identify the services (needs --scope)
  stik-net audit [tgt]  full pass: discover, scan, fingerprint, rank findings (needs --scope)
  stik-net topo         draw the network map from the last audit (--from, --scope, --out)
  stik-net diff         what changed between the last two audits (scans nothing)
  stik-net daemon       background watcher; alerts on a new device, rogue DHCP, or ARP spoofing
  stik-net service ...  install/uninstall/status the boot service (needs sudo)
  stik-net name <who>   name a device (by name, hostname, IP, or MAC)
  stik-net forget <who> remove a device from the registry

Flags:
  --verbose, -v     show MAC addresses and raw details
  --notify <target> where daemon alerts go (repeatable). Targets:
                      desktop                 native desktop notification (default)
                      ntfy://[server/]topic   push to an ntfy topic
                      https://…               POST the event as JSON to a webhook
                    Or set STIK_NOTIFY=target1,target2 in the environment.
  --engine <name>   ports/audit: connect (default, unprivileged), syn (half-open,
                    needs sudo), or auto. A fallback to connect is always reported.
  --no-fingerprint  ports: list open ports only; don't identify the services
  --out <file>      audit/topo: also write the self-contained HTML report/map here
  --from <run>      topo/diff: a saved run ("last", or a path) — no scanning
  --to <run>        diff: the newer run to compare against (default: the latest)
  --diff            audit: after scanning, show what changed since the last run
  --ascii           topo: print the tree even when writing an HTML map
  --fail-on <sev>   audit: exit 1 when a finding reaches this severity (default high)
                    audit exits 0 when clean, 1 on findings, 2 if the run failed
  --help, -h        this help
  --version, -V     version

The watcher (status, devices, watch, daemon) is passive: listen-only, broadcast/
multicast traffic only, for networks you own. The active auditor (discover, ports,
audit) only runs against targets you list in an explicit --scope file, and
probes nothing outside it.
`
