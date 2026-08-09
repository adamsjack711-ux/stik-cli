//go:build linux

package service

import (
	"strings"
	"testing"
)

func TestRenderUnit(t *testing.T) {
	out, err := render(Config{
		ExecPath:   "/usr/local/bin/stik-net",
		DaemonArgs: []string{"daemon", "--notify", "ntfy://ntfy.sh/home"},
		Env:        map[string]string{"STIK_HOME": "/var/lib/stik-net"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/stik-net daemon --notify ntfy://ntfy.sh/home",
		"Environment=STIK_HOME=/var/lib/stik-net",
		"Restart=on-failure",
		"WantedBy=multi-user.target",
		"User=root",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unit missing %q\n---\n%s", want, out)
		}
	}
}

func TestShellJoinQuotesSpaces(t *testing.T) {
	got := shellJoin([]string{"/opt/my apps/stik-net", "daemon"})
	if !strings.Contains(got, `"/opt/my apps/stik-net"`) {
		t.Errorf("shellJoin didn't quote a path with a space: %q", got)
	}
}

func TestUnitPathIsSystemd(t *testing.T) {
	if got := UnitPath(); got != "/etc/systemd/system/stik-net.service" {
		t.Errorf("UnitPath() = %q", got)
	}
}
