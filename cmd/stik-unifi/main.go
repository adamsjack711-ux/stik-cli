// Command stik-unifi reads a UniFi controller and draws what is separated from
// what. It is a companion to stik-net, not part of it.
//
// stik-net's whole promise is that it listens and never transmits. This tool
// authenticates to a controller with admin credentials and asks it questions —
// a different activity with different consequences — so it ships as a separate
// binary. That way the passive watcher's guarantee stays literally true, and
// running one never implies running the other.
//
// It is read-only by construction: the client exposes GET and nothing else, and
// never reads the CSRF token a controller requires before accepting a write.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/adamsjack711-ux/stik-cli/internal/ui"
	"github.com/adamsjack711-ux/stik-cli/internal/unifi"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	cfg, err := parseFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stik-unifi: "+err.Error())
		return 2
	}
	if cfg.help {
		fmt.Print(helpText)
		return 0
	}
	if cfg.version {
		fmt.Println("stik-unifi " + version)
		return 0
	}
	if cfg.host == "" {
		fmt.Fprintln(os.Stderr, "stik-unifi: --host <controller> is required (e.g. --host 192.168.1.1)")
		return 2
	}

	style := ui.NewStyle(os.Stdout)

	username := cfg.username
	if username == "" {
		username = os.Getenv("UNIFI_USER")
	}
	password := os.Getenv("UNIFI_PASS")
	if username == "" {
		fmt.Fprintln(os.Stderr, "stik-unifi: --user <name> is required (or set UNIFI_USER)")
		return 2
	}
	if password == "" {
		// Read from the terminal rather than a flag: a password in argv is
		// visible to every other process on the machine and lands in shell
		// history.
		prompted, err := promptPassword(username, cfg.host)
		if err != nil {
			fmt.Fprintln(os.Stderr, "stik-unifi: "+err.Error())
			return 2
		}
		password = prompted
	}

	client, err := unifi.New(cfg.host, cfg.site, !cfg.verifyTLS)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stik-unifi: "+err.Error())
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := client.Login(ctx, username, password, cfg.token); err != nil {
		var twoFA unifi.TwoFactorError
		if errors.As(err, &twoFA) {
			fmt.Fprintln(os.Stderr, "stik-unifi: "+twoFA.Error())
			return 2
		}
		fmt.Fprintln(os.Stderr, "stik-unifi: "+err.Error())
		return 1
	}

	snap, err := client.Fetch(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stik-unifi: "+err.Error())
		return 1
	}

	m := unifi.Build(cfg.site, snap)
	if cfg.jsonOut {
		return writeJSON(m)
	}
	unifi.WriteText(os.Stdout, style, m)
	return 0
}

func promptPassword(user, host string) (string, error) {
	fmt.Fprintf(os.Stderr, "password for %s@%s: ", user, host)
	if !term.IsTerminal(int(syscall.Stdin)) {
		// Not a terminal: read a line rather than failing, so the tool still
		// works from a pipe — but never echo it back.
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return "", errors.New("no password supplied (set UNIFI_PASS or run interactively)")
		}
		return strings.TrimSpace(line), nil
	}
	raw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(raw), nil
}

type config struct {
	host      string
	site      string
	username  string
	token     string
	jsonOut   bool
	verifyTLS bool
	help      bool
	version   bool
}

func parseFlags(args []string) (config, error) {
	cfg := config{site: "default"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func(name string) (string, error) {
			if strings.HasPrefix(a, name+"=") {
				return strings.TrimPrefix(a, name+"="), nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch {
		case a == "map":
			// the only verb, accepted so the command reads as a sentence
		case a == "--host" || strings.HasPrefix(a, "--host="):
			v, err := next("--host")
			if err != nil {
				return cfg, err
			}
			cfg.host = v
		case a == "--site" || strings.HasPrefix(a, "--site="):
			v, err := next("--site")
			if err != nil {
				return cfg, err
			}
			cfg.site = v
		case a == "--user" || strings.HasPrefix(a, "--user="):
			v, err := next("--user")
			if err != nil {
				return cfg, err
			}
			cfg.username = v
		case a == "--token" || strings.HasPrefix(a, "--token="):
			v, err := next("--token")
			if err != nil {
				return cfg, err
			}
			cfg.token = v
		case a == "--json":
			cfg.jsonOut = true
		case a == "--verify-tls":
			cfg.verifyTLS = true
		case a == "--help" || a == "-h":
			cfg.help = true
		case a == "--version" || a == "-V":
			cfg.version = true
		case a == "--password" || strings.HasPrefix(a, "--password="):
			return cfg, errors.New("there is no --password flag on purpose: a password in argv is " +
				"visible to every process on the machine. Use UNIFI_PASS, or let the prompt ask")
		default:
			return cfg, fmt.Errorf("unknown argument %q", a)
		}
	}
	return cfg, nil
}

const helpText = `stik-unifi — read a UniFi controller and show what is separated from what.

Usage:
  stik-unifi map --host <controller> [--site default] --user <admin>

Flags:
  --host <addr>     controller address (e.g. 192.168.1.1 or unifi.local)
  --site <name>     site name, default "default"
  --user <name>     local admin username (or set UNIFI_USER)
  --token <code>    2FA code, when the controller asks for one
  --json            emit the map as JSON instead of text
  --verify-tls      verify the controller's certificate (off by default:
                    UniFi controllers ship a self-signed one)
  --help, -h        this help
  --version, -V     version

The password is read from UNIFI_PASS or prompted for. There is deliberately no
--password flag: a password in argv is visible to every other process on the
machine and ends up in shell history.

This is a companion to stik-net, not part of it. stik-net listens and never
transmits; this tool authenticates to a controller and asks it questions, which
is a different activity with different consequences — so it is a separate
binary and running one never implies running the other.

It is read-only by construction: it issues GET requests only, and never reads
the CSRF token a UniFi controller requires before it will accept a change.
`
