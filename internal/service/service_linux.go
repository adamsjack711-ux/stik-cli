//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const linuxUnitName = "stik-net.service"

// UnitPath is the systemd system-unit location (enabled at boot, runs as root).
func UnitPath() string {
	return filepath.Join("/etc/systemd/system", linuxUnitName)
}

// SystemStoreDir is the root-owned baseline directory the service reads/writes,
// kept separate from the user's ~/.stik so ownership never clashes.
func SystemStoreDir() string {
	return "/var/lib/stik-net"
}

const unitTmpl = `[Unit]
Description=stik-net passive network watcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.ExecStart}}
{{- range $k, $v := .Env}}
Environment={{$k}}={{$v}}
{{- end}}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`

// render produces the unit contents for cfg.
func render(cfg Config) (string, error) {
	return renderTemplate("unit", unitTmpl, struct {
		ExecStart string
		Env       map[string]string
	}{
		ExecStart: shellJoin(append([]string{cfg.ExecPath}, cfg.DaemonArgs...)),
		Env:       cfg.Env,
	})
}

// Install writes the unit, reloads systemd, and enables+starts it.
func Install(cfg Config) (string, error) {
	path := UnitPath()
	content, err := render(cfg)
	if err != nil {
		return "", err
	}
	if err := writeFile(path, content, 0o644); err != nil {
		return "", err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", "--now", linuxUnitName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl enable: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return path, nil
}

// Uninstall disables+stops the unit and removes it.
func Uninstall() (string, error) {
	path := UnitPath()
	_ = exec.Command("systemctl", "disable", "--now", linuxUnitName).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return path, nil
}

// Status reports systemd's active-state for the unit (active/inactive/failed…).
func Status() (string, error) {
	out, _ := exec.Command("systemctl", "is-active", linuxUnitName).Output()
	state := strings.TrimSpace(string(out))
	if state == "" {
		state = "unknown"
	}
	return state, nil
}

// shellJoin renders an argv as a single command line, quoting any argument that
// contains whitespace so systemd's ExecStart parses it as one token.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			quoted[i] = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		} else {
			quoted[i] = a
		}
	}
	return strings.Join(quoted, " ")
}
