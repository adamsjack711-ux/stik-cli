// Package service installs stik-net's daemon as a boot service — a launchd
// LaunchDaemon on macOS, a systemd system unit on Linux — so the passive watch
// survives logout and reboot without anyone re-running it by hand. Both run as
// root, because raw packet capture requires it.
//
// The platform files (service_darwin.go / service_linux.go) own the unit
// template and the load/unload commands; this file holds the shared Config and
// the file helper. Install/Uninstall/Status/UnitPath/SystemStoreDir are declared
// per platform.
package service

import (
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// Config is what the platform installer bakes into the unit file.
type Config struct {
	ExecPath   string            // absolute path to the stik-net binary
	DaemonArgs []string          // full daemon args, e.g. ["daemon","--notify","ntfy://ntfy.sh/x"]
	Env        map[string]string // environment for the unit, e.g. {"STIK_HOME": "/var/lib/stik-net"}
}

// renderTemplate expands tmpl with data into a string.
func renderTemplate(name, tmpl string, data any) (string, error) {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// writeFile writes content to path (creating parent dirs), replacing any
// existing file, with the given mode.
func writeFile(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), mode)
}
