package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/alert"
	"github.com/adamsjack711-ux/stik-cli/internal/capture"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
	"github.com/adamsjack711-ux/stik-cli/internal/scan"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// cmdStatus is the default `stik`: on first run it onboards; after that it's the
// one-line, usually-boring verdict.
func (a *app) cmdStatus() error {
	reg, firstRun, err := a.load()
	if err != nil {
		return err
	}
	if firstRun {
		return a.onboard(reg)
	}
	ui.Status(a.out, a.style, reg.Devices(), time.Now())
	return nil
}

func (a *app) cmdDevices(verbose bool) error {
	reg, firstRun, err := a.load()
	if err != nil {
		return err
	}
	if firstRun {
		fmt.Fprintln(a.out, a.style.Dim("No baseline yet.")+" Run "+a.style.Bold("stik")+" to set one up.")
		return nil
	}
	ui.DeviceList(a.out, a.style, reg.Devices(), verbose, time.Now())
	return nil
}

func (a *app) cmdWatch() error {
	reg, _, err := a.load()
	if err != nil {
		return err
	}
	cap, err := capture.Open("")
	if err != nil {
		return err
	}
	defer cap.Close()

	ctx, cancel := signalContext()
	defer cancel()

	watchErr := ui.Watch(ctx, reg, cap.Interface(), cap.Run, nil)
	if saveErr := a.save(reg); saveErr != nil && watchErr == nil {
		watchErr = saveErr
	}
	return watchErr
}

func (a *app) cmdDaemon(notifySpecs []string) error {
	reg, firstRun, err := a.load()
	if err != nil {
		return err
	}
	if firstRun {
		return errors.New("no baseline yet — run `stik` once to set one up before starting the daemon")
	}

	notifier, err := alert.Sinks(resolveNotifySpecs(notifySpecs))
	if err != nil {
		return err
	}

	cap, err := capture.Open("")
	if err != nil {
		return err
	}
	defer cap.Close()

	ctx, cancel := signalContext()
	defer cancel()

	fmt.Fprintf(a.out, "%s watching %s — alerts via %s when a new device (or a rogue DHCP server) appears. Ctrl+C to stop.\n",
		a.style.Green("stik daemon"), a.style.Cyan(cap.Interface()), a.style.Bold(notifier.Describe()))

	// deliver pushes an event to every configured sink off the capture goroutine,
	// logging any sink failures without ever blocking packet handling.
	deliver := func(ev alert.Event) {
		go func() {
			for _, e := range notifier.Deliver(ev) {
				fmt.Fprintln(a.err, "stik: alert "+e.Error())
			}
		}()
	}
	// persist writes the registry immediately so an appearance survives a crash.
	// Safe: called on the same goroutine that just mutated the registry.
	persist := func() {
		if err := a.save(reg); err != nil {
			fmt.Fprintln(a.err, "stik: "+err.Error())
		}
	}

	sc := scan.New(reg, time.Now)
	sc.OnNew = func(d *model.Device) {
		fmt.Fprintf(a.out, "%s new device: %s%s%s%s, first seen %s\n",
			a.style.Yellow("⚠"), d.Display(), ipSuffix(d), hostSuffix(d), privSuffix(d), ui.ClockTime(d.FirstSeen))
		deliver(eventFor(alert.KindNewDevice, d, cap.Interface()))
		persist()
	}
	sc.OnDHCPServer = func(d *model.Device) {
		fmt.Fprintf(a.out, "%s possible rogue DHCP server: %s%s is handing out leases — expected only your router\n",
			a.style.Red("⚠ ⚠"), d.Display(), ipSuffix(d))
		deliver(eventFor(alert.KindRogueDHCP, d, cap.Interface()))
		persist()
	}

	runErr := cap.Run(ctx, sc.Handle)
	if saveErr := a.save(reg); saveErr != nil && runErr == nil {
		runErr = saveErr
	}
	return runErr
}

// resolveNotifySpecs prefers explicit --notify flags, falling back to the
// STIK_NOTIFY environment variable (comma-separated) for daemonized setups.
func resolveNotifySpecs(flags []string) []string {
	if len(flags) > 0 {
		return flags
	}
	var specs []string
	for _, s := range strings.Split(os.Getenv("STIK_NOTIFY"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			specs = append(specs, s)
		}
	}
	return specs
}

// eventFor snapshots a device into a transport-agnostic alert event.
func eventFor(kind alert.Kind, d *model.Device, iface string) alert.Event {
	return alert.Event{
		Kind:      kind,
		MAC:       d.MAC,
		IP:        d.IP,
		Name:      d.Display(),
		Vendor:    d.Vendor,
		Hostname:  d.Hostname,
		Private:   d.Private,
		FirstSeen: d.FirstSeen,
		Interface: iface,
	}
}

func (a *app) cmdName(rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: stik name <device> [new name]")
	}
	reg, firstRun, err := a.load()
	if err != nil {
		return err
	}
	if firstRun {
		return errors.New("no devices yet — run `stik` first")
	}

	dev, err := a.resolve(reg, rest[0])
	if err != nil {
		return err
	}
	name := strings.TrimSpace(strings.Join(rest[1:], " "))
	if name == "" {
		name, _ = promptLine(a.out, "New name for "+dev.Display()+": ")
		name = strings.TrimSpace(name)
		if name == "" {
			return errors.New("no name given")
		}
	}
	reg.Accept(dev.MAC, name) // naming also accepts the device into the baseline
	if err := a.save(reg); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "%s named %s\n", a.style.Green("✓"), a.style.Bold(name))
	return nil
}

func (a *app) cmdForget(rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: stik forget <device>")
	}
	reg, firstRun, err := a.load()
	if err != nil {
		return err
	}
	if firstRun {
		return errors.New("no devices yet — nothing to forget")
	}

	dev, err := a.resolve(reg, strings.Join(rest, " "))
	if err != nil {
		return err
	}
	name := dev.Display()
	reg.Forget(dev.MAC)
	if err := a.save(reg); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "%s forgot %s. It'll be flagged as new if it comes back.\n", a.style.Green("✓"), a.style.Bold(name))
	return nil
}

// onboard runs the first-use flow: a passive sweep, then the naming wizard.
func (a *app) onboard(reg *registry.Registry) error {
	fmt.Fprintf(a.out, "%s  Welcome to stik. Let's learn what's on your network.\n", a.style.Bold("👋"))
	fmt.Fprintf(a.out, "%s\n", a.style.Dim(fmt.Sprintf("Listening passively for %ds — stik only ever listens, it never sends traffic.", int(scanSeconds().Seconds()))))

	if err := a.sweepWithSpinner(reg, scanSeconds()); err != nil {
		return err
	}

	devices := reg.SortedByLastSeen()
	if len(devices) == 0 {
		fmt.Fprintln(a.out, a.style.Dim("Didn't hear from any devices yet — your network may just be quiet."))
		fmt.Fprintln(a.out, "Try "+a.style.Bold("stik watch")+" and leave it running for a bit.")
		return a.save(reg) // write an empty baseline so we don't re-onboard every run
	}
	ui.RunWizard(os.Stdin, a.out, a.style, reg, devices)
	return a.save(reg)
}

// sweepWithSpinner runs a passive sweep while showing a live "heard N devices"
// spinner on a TTY. On non-TTY output the spinner is suppressed.
func (a *app) sweepWithSpinner(reg *registry.Registry, d time.Duration) error {
	var count int32
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.sweep(reg, d, func() { atomic.AddInt32(&count, 1) })
	}()

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case err := <-errCh:
			if a.style.ColorEnabled() {
				fmt.Fprint(a.out, "\r\x1b[2K")
			}
			return err
		case <-ticker.C:
			if a.style.ColorEnabled() {
				fmt.Fprintf(a.out, "\r  %s  heard %d %s so far…",
					frames[i%len(frames)], atomic.LoadInt32(&count), pluralWord(int(atomic.LoadInt32(&count))))
				i++
			}
		}
	}
}

func (a *app) resolve(reg *registry.Registry, query string) (*model.Device, error) {
	matches := reg.Find(query)
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no device matches %q — see `stik devices`", query)
	case 1:
		return matches[0], nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%q matches %d devices — be more specific:\n", query, len(matches))
		for _, d := range matches {
			fmt.Fprintf(&b, "  • %s (%s)\n", d.Display(), d.MAC)
		}
		return nil, errors.New(strings.TrimRight(b.String(), "\n"))
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func promptLine(out *os.File, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line), err
}

func hostSuffix(d *model.Device) string {
	if d.Hostname != "" {
		return " (" + d.Hostname + ")"
	}
	return ""
}

// ipSuffix renders the device's IP for the one-line daemon log, e.g. " at
// 192.168.1.42". Empty when the device hasn't revealed an address yet.
func ipSuffix(d *model.Device) string {
	if d.IP != "" {
		return " at " + d.IP
	}
	return ""
}

// privSuffix flags a randomized (locally-administered) MAC in the daemon's
// one-line log. The device may still be identifiable by an announced name.
func privSuffix(d *model.Device) string {
	if d.Private {
		return " · randomized MAC"
	}
	return ""
}

func pluralWord(n int) string {
	if n == 1 {
		return "device"
	}
	return "devices"
}
