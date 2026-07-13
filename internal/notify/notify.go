// Package notify sends a desktop notification — the alert that actually reaches
// the user. Nobody watches a TUI all day; the whole point of the daemon is that
// the tap on the shoulder comes to you. Kept dependency-free by shelling out to
// each platform's native notifier.
package notify

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// Send posts a desktop notification. A missing notifier is reported as an error
// so the caller can fall back to printing, rather than failing silently.
func Send(title, message string) error {
	switch runtime.GOOS {
	case "darwin":
		return sendDarwin(title, message)
	case "linux":
		return sendLinux(title, message)
	default:
		return errors.New("desktop notifications aren't supported on this platform")
	}
}

func sendDarwin(title, message string) error {
	// Prefer terminal-notifier if installed (nicer, clickable); else osascript.
	if path, err := exec.LookPath("terminal-notifier"); err == nil {
		return exec.Command(path, "-title", title, "-message", message).Run()
	}
	script := "display notification \"" + escapeAppleScript(message) +
		"\" with title \"" + escapeAppleScript(title) + "\""
	return exec.Command("osascript", "-e", script).Run()
}

func sendLinux(title, message string) error {
	path, err := exec.LookPath("notify-send")
	if err != nil {
		return errors.New("notify-send not found (install libnotify-bin)")
	}
	return exec.Command(path, title, message).Run()
}

// escapeAppleScript makes a string safe to embed in an AppleScript string
// literal by escaping backslashes and double quotes.
func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
