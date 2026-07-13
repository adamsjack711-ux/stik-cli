// Command stik is a passive network watcher. nmap tells you what's on your
// network right now; stik remembers what's normal and tells you when that
// changes. It listens only to broadcast/multicast traffic (ARP, mDNS, DHCP),
// never transmits, and is meant for networks you own.
package main

import (
	"fmt"
	"os"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	verbose := false
	var positional []string
	for _, a := range args {
		switch a {
		case "--verbose", "-v":
			verbose = true
		case "--help", "-h", "help":
			fmt.Print(helpText)
			return 0
		case "--version", "-V", "version":
			fmt.Println("stik " + version)
			return 0
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
		err = a.cmdDaemon()
	case "name":
		err = a.cmdName(rest)
	case "forget":
		err = a.cmdForget(rest)
	default:
		fmt.Fprintf(os.Stderr, "stik: unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, helpText)
		return 2
	}

	if err != nil {
		if msg, ok := friendlyError(a.style, err); ok {
			fmt.Fprintln(os.Stderr, msg)
			return 1
		}
		fmt.Fprintln(os.Stderr, "stik: "+err.Error())
		return 1
	}
	return 0
}

const helpText = `stik — a passive watcher that tells you what's on your network,
and taps you on the shoulder when something new shows up.

Usage:
  stik              status: is anything new? (runs the setup wizard on first use)
  stik devices      list every device in plain terms (--verbose for MACs & details)
  stik watch        live view; new devices highlight as they appear
  stik daemon       background watcher; desktop-notifies on a new device
  stik name <who>   name a device (by name, hostname, IP, or MAC)
  stik forget <who> remove a device from the registry

Flags:
  --verbose, -v     show MAC addresses and raw details
  --help, -h        this help
  --version, -V     version

stik is passive (listen-only), sees broadcast/multicast traffic only, and is
for networks you own. It never scans, probes, or transmits.
`
