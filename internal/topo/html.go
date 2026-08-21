package topo

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// Detail is the per-node payload the map's side panel shows on click: what the
// scan found on that host, and what the rules made of it.
type Detail struct {
	ID       string          `json:"id"`
	Services []string        `json:"services,omitempty"`
	Findings []DetailFinding `json:"findings,omitempty"`
}

// DetailFinding is a finding trimmed to what fits in the panel.
type DetailFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Port     int    `json:"port,omitempty"`
	ID       string `json:"id"`
}

// View is a graph plus everything the page needs to render it standalone.
type View struct {
	Graph    model.Graph
	Details  []Detail
	Title    string
	Subtitle string
}

// ViewFrom assembles the drawable view from scan results.
func ViewFrom(g model.Graph, hosts []model.Host, findings []model.Finding) View {
	byHost := map[string][]DetailFinding{}
	for _, f := range findings {
		byHost[f.Host] = append(byHost[f.Host], DetailFinding{
			Severity: string(f.Severity), Title: f.Title, Port: f.Port, ID: f.ID,
		})
	}
	details := make([]Detail, 0, len(hosts))
	for _, h := range hosts {
		d := Detail{ID: h.IP, Findings: byHost[h.IP]}
		for _, s := range h.Services {
			if s.State != model.StateOpen {
				continue
			}
			d.Services = append(d.Services, portLabel(s))
		}
		details = append(details, d)
	}
	return View{Graph: g, Details: details}
}

func portLabel(s model.Service) string {
	label := s.Name
	if s.Product != "" {
		label = s.Product
		if s.Version != "" {
			label += " " + s.Version
		}
	}
	if label == "" {
		label = "unknown"
	}
	return itoa(s.Port) + "/tcp " + label
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Fragment renders the map as an embeddable <section>: markup, scoped styles
// and an inline script, with no external asset of any kind. The data reaches
// the script as JSON produced by encoding/json, which escapes <, > and & — so
// a hostile device name cannot close the script tag it travels inside.
func Fragment(v View) (template.HTML, error) {
	graphJSON, err := json.Marshal(v.Graph)
	if err != nil {
		return "", err
	}
	detailJSON, err := json.Marshal(v.Details)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = fragmentTemplate.Execute(&buf, struct {
		Graph, Details template.JS
		Nodes          []model.Node
		Inferred       int
	}{
		Graph:    template.JS(graphJSON),
		Details:  template.JS(detailJSON),
		Nodes:    v.Graph.Nodes,
		Inferred: countInferred(v.Graph),
	})
	if err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

// WriteHTML writes the standalone map page for `stik-net topo --out`.
func WriteHTML(w io.Writer, v View) error {
	frag, err := Fragment(v)
	if err != nil {
		return err
	}
	title := v.Title
	if title == "" {
		title = "Network map"
	}
	return pageTemplate.Execute(w, struct {
		Title    string
		Subtitle string
		Map      template.HTML
	}{Title: title, Subtitle: v.Subtitle, Map: frag})
}

func countInferred(g model.Graph) int {
	n := 0
	for _, e := range g.Edges {
		if e.Inferred {
			n++
		}
	}
	return n
}

var fragmentTemplate = template.Must(template.New("map").Parse(mapFragment))

var pageTemplate = template.Must(template.New("page").Parse(mapPage))
