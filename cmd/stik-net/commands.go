package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/alert"
	"github.com/adamsjack711-ux/stik-cli/internal/capture"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
	"github.com/adamsjack711-ux/stik-cli/internal/scan"
	"github.com/adamsjack711-ux/stik-cli/internal/service"
	"github.com/adamsjack711-ux/stik-cli/internal/ui"
)

// cmdStatus is the default `stik-net`: on first run it onboards; after that it's the
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
		fmt.Fprintln(a.out, a.style.Dim("No baseline yet.")+" Run "+a.style.Bold("stik-net")+" to set one up.")
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
		return errors.New("no baseline yet — run `stik-net` once to set one up before starting the daemon")
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

	fmt.Fprintf(a.out, "%s watching %s — alerts via %s on a new device, a rogue DHCP server, or ARP spoofing. Ctrl+C to stop.\n",
		a.style.Green("stik-net daemon"), a.style.Cyan(cap.Interface()), a.style.Bold(notifier.Describe()))

	// deliver pushes an event to every configured sink off the capture goroutine,
	// logging any sink failures without ever blocking packet handling.
	deliver := func(ev alert.Event) {
		go func() {
			for _, e := range notifier.Deliver(ev) {
				fmt.Fprintln(a.err, "stik-net: alert "+e.Error())
			}
		}()
	}
	// persist writes the registry immediately so an appearance survives a crash.
	// Safe: called on the same goroutine that just mutated the registry.
	persist := func() {
		if err := a.save(reg); err != nil {
			fmt.Fprintln(a.err, "stik-net: "+err.Error())
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
	sc.OnConflict = func(c scan.Conflict) {
		was := c.OldMAC
		if c.Old != nil {
			was = c.Old.Display() + " (" + c.OldMAC + ")"
		}
		claimant := "an unknown device"
		if c.New != nil {
			claimant = c.New.Display()
		}
		fmt.Fprintf(a.out, "%s possible ARP spoofing: %s is now claimed by %s (%s) — was %s\n",
			a.style.Red("⚠ ⚠"), c.IP, claimant, c.NewMAC, was)
		ev := eventFor(alert.KindARPSpoof, c.New, cap.Interface())
		ev.IP = c.IP // the contested address, not necessarily the device's own
		ev.PrevMAC = c.OldMAC
		if c.Old != nil {
			ev.PrevName = c.Old.Display()
		}
		deliver(ev)
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

// cmdService installs, removes, or reports the boot service.
func (a *app) cmdService(rest, notifySpecs []string) error {
	if len(rest) == 0 {
		return errors.New("usage: stik-net service <install|uninstall|status>")
	}
	switch rest[0] {
	case "install":
		return a.serviceInstall(notifySpecs)
	case "uninstall", "remove":
		return a.serviceUninstall()
	case "status":
		return a.serviceStatus()
	default:
		return fmt.Errorf("unknown service command %q — want install, uninstall, or status", rest[0])
	}
}

func (a *app) serviceInstall(notifySpecs []string) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the boot service needs root — try: sudo stik-net service install")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the stik-net binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	// The service runs as root off its own copy of the baseline, so its writes
	// never leave a root-owned file in the user's ~/.stik. Seed it from whatever
	// the invoking user onboarded.
	userBaseline := filepath.Join(userStikHome(), "devices.json")
	if _, err := os.Stat(userBaseline); err != nil {
		return fmt.Errorf("no baseline at %s yet — run `sudo stik-net` once to set one up before installing the service", userBaseline)
	}
	sysDir := service.SystemStoreDir()
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", sysDir, err)
	}
	if err := copyFile(userBaseline, filepath.Join(sysDir, "devices.json"), 0o600); err != nil {
		return fmt.Errorf("seeding the service baseline: %w", err)
	}

	specs := resolveNotifySpecs(notifySpecs)
	notifier, err := alert.Sinks(specs) // validate specs before baking them in
	if err != nil {
		return err
	}
	if onlyDesktop(specs) {
		fmt.Fprintln(a.out, a.style.Yellow("Note:")+" a boot service runs in the background and can't reach the desktop notifier.")
		fmt.Fprintln(a.out, "      Add a channel it can deliver to, e.g. "+a.style.Bold("--notify ntfy://ntfy.sh/your-topic")+".")
	}

	daemonArgs := []string{"daemon"}
	for _, s := range specs {
		daemonArgs = append(daemonArgs, "--notify", s)
	}

	path, err := service.Install(service.Config{
		ExecPath:   exe,
		DaemonArgs: daemonArgs,
		Env:        map[string]string{"STIK_HOME": sysDir},
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(a.out, "%s installed and started the stik-net service — it now runs at boot.\n", a.style.Green("✓"))
	fmt.Fprintf(a.out, "  binary:   %s\n", exe)
	fmt.Fprintf(a.out, "  unit:     %s\n", path)
	fmt.Fprintf(a.out, "  baseline: %s %s\n", filepath.Join(sysDir, "devices.json"), a.style.Dim("(a copy — re-run install to refresh it)"))
	fmt.Fprintf(a.out, "  alerts:   %s\n", notifier.Describe())
	fmt.Fprintf(a.out, "Check it with %s.\n", a.style.Bold("sudo stik-net service status"))
	return nil
}

func (a *app) serviceUninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("removing the boot service needs root — try: sudo stik-net service uninstall")
	}
	path, err := service.Uninstall()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "%s removed the stik-net service (%s).\n", a.style.Green("✓"), path)
	return nil
}

func (a *app) serviceStatus() error {
	st, err := service.Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "stik-net service: %s\n", st)
	return nil
}

// userStikHome is the directory holding the invoking user's devices.json,
// seeing through sudo (SUDO_USER) and honoring an explicit STIK_HOME.
func userStikHome() string {
	if h := os.Getenv("STIK_HOME"); h != "" {
		return h
	}
	home := ""
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			home = u.HomeDir
		}
	}
	if home == "" {
		if u, err := user.Current(); err == nil {
			home = u.HomeDir
		}
	}
	return filepath.Join(home, ".stik")
}

// onlyDesktop reports whether the notify specs resolve to desktop-only delivery
// (including the empty default), which a background service can't reach.
func onlyDesktop(specs []string) bool {
	if len(specs) == 0 {
		return true
	}
	for _, s := range specs {
		if t := strings.TrimSpace(s); t != "" && t != "desktop" {
			return false
		}
	}
	return true
}

// copyFile copies src to dst with the given mode, truncating any existing file.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (a *app) cmdName(rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: stik-net name <device> [new name]")
	}
	reg, firstRun, err := a.load()
	if err != nil {
		return err
	}
	if firstRun {
		return errors.New("no devices yet — run `stik-net` first")
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
		return errors.New("usage: stik-net forget <device>")
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
	fmt.Fprintf(a.out, "%s  Welcome to stik-net. Let's learn what's on your network.\n", a.style.Bold("👋"))
	fmt.Fprintf(a.out, "%s\n", a.style.Dim(fmt.Sprintf("Listening passively for %ds — stik-net only ever listens, it never sends traffic.", int(scanSeconds().Seconds()))))

	if err := a.sweepWithSpinner(reg, scanSeconds()); err != nil {
		return err
	}

	devices := reg.SortedByLastSeen()
	if len(devices) == 0 {
		fmt.Fprintln(a.out, a.style.Dim("Didn't hear from any devices yet — your network may just be quiet."))
		fmt.Fprintln(a.out, "Try "+a.style.Bold("stik-net watch")+" and leave it running for a bit.")
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
		return nil, fmt.Errorf("no device matches %q — see `stik-net devices`", query)
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
