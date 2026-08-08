// Command stik-net is a passive network watcher. nmap tells you what's on your
// network right now; stik-net remembers what's normal and tells you when that
// changes. It listens only to broadcast/multicast traffic (ARP, mDNS, DHCP),
// never transmits, and is meant for networks you own.
package main

import (
	"fmt"
	"os"
	"strings"
)

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
	case "daemon":
		err = a.cmdDaemon(notifySpecs)
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
		if msg, ok := friendlyError(a.style, err); ok {
			fmt.Fprintln(os.Stderr, msg)
			return 1
		}
		fmt.Fprintln(os.Stderr, "stik-net: "+err.Error())
		return 1
	}
	return 0
}

const helpText = `stik-net — a passive watcher that tells you what's on your network,
and taps you on the shoulder when something new shows up.

Usage:
  stik-net              status: is anything new? (runs the setup wizard on first use)
  stik-net devices      list every device in plain terms (--verbose for MACs & details)
  stik-net watch        live view; new devices highlight as they appear
  stik-net daemon       background watcher; alerts on a new device (and rogue DHCP)
  stik-net name <who>   name a device (by name, hostname, IP, or MAC)
  stik-net forget <who> remove a device from the registry

Flags:
  --verbose, -v     show MAC addresses and raw details
  --notify <target> where daemon alerts go (repeatable). Targets:
                      desktop                 native desktop notification (default)
                      ntfy://[server/]topic   push to an ntfy topic
                      https://…               POST the event as JSON to a webhook
                    Or set STIK_NOTIFY=target1,target2 in the environment.
  --help, -h        this help
  --version, -V     version

stik-net is passive (listen-only), sees broadcast/multicast traffic only, and is
for networks you own. It never scans, probes, or transmits.
`
