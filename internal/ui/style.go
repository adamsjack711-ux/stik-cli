// Package ui renders stik's human-facing output: the one-line status verdict,
// the device list, the first-run naming wizard, and the live watch view.
package ui

import (
	"fmt"
	"os"
	"time"
)

// Style holds whether ANSI color is enabled and applies it. Color is on only
// for a real terminal with NO_COLOR unset, so piped/redirected output stays
// clean and grep-friendly.
type Style struct {
	color bool
}

// NewStyle decides on color from the given stream and the environment.
func NewStyle(f *os.File) Style {
	if os.Getenv("NO_COLOR") != "" {
		return Style{color: false}
	}
	info, err := f.Stat()
	if err != nil {
		return Style{color: false}
	}
	return Style{color: info.Mode()&os.ModeCharDevice != 0}
}

func (s Style) wrap(code, text string) string {
	if !s.color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// ColorEnabled reports whether ANSI color/animation is active (i.e. a TTY).
func (s Style) ColorEnabled() bool { return s.color }

func (s Style) Green(t string) string  { return s.wrap("32", t) }
func (s Style) Yellow(t string) string { return s.wrap("33", t) }
func (s Style) Red(t string) string    { return s.wrap("31", t) }
func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Cyan(t string) string   { return s.wrap("36", t) }

// HumanSince renders a duration the way a person would say it.
func HumanSince(t, now time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return "just now"
	case d < 2*time.Minute:
		return "1 minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 2*time.Hour:
		return "1 hour ago"
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// ClockTime renders just the wall-clock time in the viewer's local zone, e.g.
// "14:32" — times loaded from the store may be in UTC, but people read local.
func ClockTime(t time.Time) string {
	return t.Local().Format("15:04")
}
