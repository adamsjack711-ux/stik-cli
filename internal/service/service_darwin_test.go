//go:build darwin

package service

import (
	"strings"
	"testing"
)

func TestRenderPlist(t *testing.T) {
	out, err := render(Config{
		ExecPath:   "/usr/local/bin/stik-net",
		DaemonArgs: []string{"daemon", "--notify", "ntfy://ntfy.sh/home"},
		Env:        map[string]string{"STIK_HOME": "/Library/Application Support/stik-net"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"<string>ca.stik-net.daemon</string>",
		"<string>/usr/local/bin/stik-net</string>",
		"<string>daemon</string>",
		"<string>ntfy://ntfy.sh/home</string>",
		"<key>STIK_HOME</key><string>/Library/Application Support/stik-net</string>",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><true/>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plist missing %q\n---\n%s", want, out)
		}
	}
}

func TestUnitPathIsLaunchDaemon(t *testing.T) {
	if got := UnitPath(); got != "/Library/LaunchDaemons/ca.stik-net.daemon.plist" {
		t.Errorf("UnitPath() = %q", got)
	}
}
