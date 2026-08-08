package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/dissect"
	"github.com/adamsjack711-ux/stik-cli/internal/model"
	"github.com/adamsjack711-ux/stik-cli/internal/registry"
	tea "github.com/charmbracelet/bubbletea"
)

// FrameSource runs a passive capture, calling handle for each raw frame until
// ctx is cancelled. Abstracting it lets `watch` be driven by the real capture
// or, in principle, a replayed one.
type FrameSource func(ctx context.Context, handle func([]byte)) error

// highlightFor is how long a freshly-appeared device stays visually flagged.
const highlightFor = 20 * time.Second

// Watch runs the live TUI: devices appear in real time and new ones highlight.
// onNew fires once per never-before-seen device (the daemon uses it to notify).
// When Watch returns, the registry holds everything observed during the session.
func Watch(ctx context.Context, reg *registry.Registry, iface string, src FrameSource, onNew func(*model.Device)) error {
	m := &watchModel{
		reg:       reg,
		iface:     iface,
		style:     Style{color: true}, // the TUI owns the screen, so color is safe
		highlight: map[string]time.Time{},
		onNew:     onNew,
	}
	p := tea.NewProgram(m, tea.WithContext(ctx))

	// Dissect off the UI goroutine (it's pure); fold into the registry inside
	// Update, which is single-threaded — so the registry is never raced.
	go func() {
		_ = src(ctx, func(data []byte) {
			if obs, ok := dissect.Frame(data); ok {
				p.Send(obsMsg(obs))
			}
		})
	}()

	_, err := p.Run()
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

type obsMsg model.Observation
type tickMsg time.Time

type watchModel struct {
	reg       *registry.Registry
	iface     string
	style     Style
	highlight map[string]time.Time
	onNew     func(*model.Device)
	newCount  int
	now       time.Time
	width     int
	quitting  bool
}

func (m *watchModel) Init() tea.Cmd {
	m.now = time.Now()
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tickMsg:
		m.now = time.Time(msg)
		return m, tick()
	case obsMsg:
		now := time.Now()
		m.now = now
		dev, isNew := m.reg.Observe(model.Observation(msg), now)
		if isNew && dev != nil {
			m.highlight[dev.MAC] = now
			m.newCount++
			if m.onNew != nil {
				m.onNew(dev)
			}
		}
	}
	return m, nil
}

func (m *watchModel) View() string {
	if m.quitting {
		return ""
	}
	s := m.style
	var b strings.Builder

	fmt.Fprintf(&b, "%s  %s  ·  watching %s  ·  %s\n",
		s.Bold("stik-net"), s.Dim("passive network watch"), s.Cyan(m.iface), s.Dim(ClockTime(m.now)))
	fmt.Fprintln(&b, s.Dim(strings.Repeat("─", 48)))

	devices := m.reg.SortedByLastSeen()
	if len(devices) == 0 {
		fmt.Fprintf(&b, "\n%s\n", s.Dim("listening… devices will appear as they speak."))
	}
	for _, d := range devices {
		isNew := m.isHighlighted(d.MAC)
		bullet := s.Green("•")
		tag := ""
		name := d.Display()
		if isNew {
			bullet = s.Yellow("●")
			tag = s.Yellow("  ← new")
			name = s.Bold(name)
		} else if !d.Known {
			bullet = s.Yellow("•")
		}
		host := ""
		if d.Hostname != "" {
			host = s.Dim("  " + d.Hostname)
		}
		fmt.Fprintf(&b, "%s %s%s%s\n", bullet, name, host, tag)
		fmt.Fprintf(&b, "   %s\n", s.Dim(fmt.Sprintf("last seen %s", HumanSince(d.LastSeen, m.now))))
	}

	fmt.Fprintln(&b, s.Dim(strings.Repeat("─", 48)))
	fmt.Fprintf(&b, "%s total  ·  %s new this session  ·  %s\n",
		s.Bold(fmt.Sprint(len(devices))), s.Yellow(fmt.Sprint(m.newCount)), s.Dim("press q to quit"))
	return b.String()
}

func (m *watchModel) isHighlighted(mac string) bool {
	t, ok := m.highlight[mac]
	return ok && m.now.Sub(t) < highlightFor
}
