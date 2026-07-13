package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/capture"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
	"github.com/adamsjack711-ux/stik-cli/internal/scan"
	"github.com/adamsjack711-ux/stik-cli/internal/store"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// app bundles the process-wide pieces the commands share.
type app struct {
	store *store.Store
	out   *os.File
	err   *os.File
	style ui.Style
}

func newApp() *app {
	st := store.New(store.DefaultPath())
	st.Warn = func(msg string) { fmt.Fprintln(os.Stderr, "stik: "+msg) }
	return &app{
		store: st,
		out:   os.Stdout,
		err:   os.Stderr,
		style: ui.NewStyle(os.Stdout),
	}
}

// load reads the registry from disk. FirstRun reports whether this is the very
// first invocation (no store file yet), which triggers onboarding.
func (a *app) load() (*registry.Registry, bool, error) {
	snap, err := a.store.Load()
	if err != nil {
		return nil, false, err
	}
	return registry.New(snap.Devices), snap.FirstRun, nil
}

func (a *app) save(reg *registry.Registry) error {
	return a.store.Save(reg.Devices())
}

// sweep runs a passive capture for the given duration, folding everything it
// hears into reg. It is the shared "look at the network now" primitive used by
// onboarding. onNew, if set, fires for each never-before-seen device.
func (a *app) sweep(reg *registry.Registry, d time.Duration, onNew func()) error {
	cap, err := capture.Open("")
	if err != nil {
		return err
	}
	defer cap.Close()

	sc := scan.New(reg, time.Now)
	if onNew != nil {
		sc.OnNew = func(_ *model.Device) { onNew() }
	}

	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return cap.Run(ctx, sc.Handle)
}

// scanSeconds is the onboarding sweep length, overridable for demos/tests.
func scanSeconds() time.Duration {
	if v := os.Getenv("STIK_SCAN_SECONDS"); v != "" {
		if n, err := time.ParseDuration(v + "s"); err == nil {
			return n
		}
	}
	return 10 * time.Second
}

// friendlyError turns the errors that capture can produce into calm, actionable
// guidance instead of a raw stack trace. Returns ("", false) if it has no
// special wording for the error.
func friendlyError(s ui.Style, err error) (string, bool) {
	var perm *capture.PermissionError
	if errors.As(err, &perm) {
		return s.Yellow("stik needs permission to watch network traffic.") + "\n" +
			"Packet capture requires elevated privileges. Try:\n\n" +
			"    " + s.Bold("sudo stik "+currentCommand()) + "\n\n" +
			s.Dim("stik only listens — it never sends traffic — but the OS still gates raw capture behind root."), true
	}
	var noif capture.NoInterfaceError
	if errors.As(err, &noif) {
		return s.Yellow("stik couldn't find an active network connection.") + "\n" +
			"Connect to Wi-Fi or Ethernet and try again.", true
	}
	return "", false
}

// currentCommand is a best-effort echo of the subcommand for the sudo hint.
func currentCommand() string {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "watch", "daemon", "devices":
			return arg
		}
	}
	return "watch"
}
