//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const darwinLabel = "ca.stik-net.daemon"

// UnitPath is the LaunchDaemon plist location (loaded at boot, runs as root).
func UnitPath() string {
	return filepath.Join("/Library/LaunchDaemons", darwinLabel+".plist")
}

// SystemStoreDir is the root-owned baseline directory the service reads/writes,
// kept separate from the user's ~/.stik so ownership never clashes.
func SystemStoreDir() string {
	return "/Library/Application Support/stik-net"
}

const logPath = "/var/log/stik-net.log"

const plistTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{{.Label}}</string>
  <key>ProgramArguments</key>
  <array>
{{- range .Args}}
    <string>{{.}}</string>
{{- end}}
  </array>
{{- if .Env}}
  <key>EnvironmentVariables</key>
  <dict>
{{- range $k, $v := .Env}}
    <key>{{$k}}</key><string>{{$v}}</string>
{{- end}}
  </dict>
{{- end}}
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{{.LogPath}}</string>
  <key>StandardErrorPath</key><string>{{.LogPath}}</string>
</dict>
</plist>
`

// render produces the plist contents for cfg.
func render(cfg Config) (string, error) {
	return renderTemplate("plist", plistTmpl, struct {
		Label   string
		LogPath string
		Args    []string
		Env     map[string]string
	}{
		Label:   darwinLabel,
		LogPath: logPath,
		Args:    append([]string{cfg.ExecPath}, cfg.DaemonArgs...),
		Env:     cfg.Env,
	})
}

// Install writes the plist and loads it into launchd.
func Install(cfg Config) (string, error) {
	path := UnitPath()
	content, err := render(cfg)
	if err != nil {
		return "", err
	}
	if err := writeFile(path, content, 0o644); err != nil {
		return "", err
	}
	// Unload any previous instance first so a re-install picks up changes.
	_ = exec.Command("launchctl", "unload", path).Run()
	if out, err := exec.Command("launchctl", "load", "-w", path).CombinedOutput(); err != nil {
		return "", fmt.Errorf("launchctl load: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return path, nil
}

// Uninstall unloads and removes the plist.
func Uninstall() (string, error) {
	path := UnitPath()
	_ = exec.Command("launchctl", "unload", "-w", path).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return path, nil
}

// Status reports whether launchd currently has the daemon loaded.
func Status() (string, error) {
	out, _ := exec.Command("launchctl", "list").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, darwinLabel) {
			return "loaded (" + strings.TrimSpace(line) + ")", nil
		}
	}
	return "not loaded", nil
}
