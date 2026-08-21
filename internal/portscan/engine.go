package portscan

import (
	"fmt"
	"time"
)

// Engine names accepted by --engine.
const (
	EngineConnect = "connect" // unprivileged TCP connect; the default
	EngineSYN     = "syn"     // privileged half-open
	EngineAuto    = "auto"    // SYN when we can, connect when we can't
)

// EngineChoice resolves an engine name into a Scanner. It exists so the
// fallback from SYN to connect is a decision the caller can see, test, and
// report — a scan that silently changed technique is a scan whose results you
// can't interpret.
type EngineChoice struct {
	Name    string
	Timeout time.Duration
	Iface   string

	// Available reports whether the privileged engine can run here. nil uses
	// the real privilege check; tests substitute their own.
	Available func() error
	// Notice receives a plain-English line whenever the choice is not what was
	// asked for. nil discards it — but nothing else may swallow the change.
	Notice func(string)
}

// Scanner returns the engine to use and the name it ended up being.
func (c EngineChoice) Scanner() (Scanner, string, error) {
	check := c.Available
	if check == nil {
		check = Available
	}

	switch c.Name {
	case "", EngineConnect:
		return ConnectScanner{Timeout: c.Timeout}, EngineConnect, nil

	case EngineSYN:
		if err := check(); err != nil {
			c.notify(fmt.Sprintf(
				"SYN scanning needs root (or CAP_NET_RAW) — %v.\n"+
					"Falling back to a connect scan, which is noisier: it completes the handshake, "+
					"so the target's application logs will show it. Re-run with sudo for a half-open scan.", err))
			return ConnectScanner{Timeout: c.Timeout}, EngineConnect, nil
		}
		return &SYNScanner{Timeout: c.Timeout, Iface: c.Iface}, EngineSYN, nil

	case EngineAuto:
		if err := check(); err != nil {
			c.notify(fmt.Sprintf("using the connect engine: SYN scanning is unavailable (%v)", err))
			return ConnectScanner{Timeout: c.Timeout}, EngineConnect, nil
		}
		return &SYNScanner{Timeout: c.Timeout, Iface: c.Iface}, EngineSYN, nil

	default:
		return nil, "", fmt.Errorf("--engine: want %s, %s or %s; got %q",
			EngineConnect, EngineSYN, EngineAuto, c.Name)
	}
}

func (c EngineChoice) notify(msg string) {
	if c.Notice != nil {
		c.Notice(msg)
	}
}
