package audit

import (
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/adamsjack711-ux/stik-cli/internal/model"
)

// WriteHTML renders the report as a single self-contained file: no scripts, no
// external stylesheets, no fonts fetched over the network. It is meant to be
// handed to someone, and a deliverable that phones home is not one.
//
// Everything the network said — banners, certificate subjects, page titles —
// reaches the page through html/template, so a hostile banner is text, not
// markup.
func WriteHTML(w io.Writer, r Report) error {
	return htmlTemplate.Execute(w, htmlView{
		Report:    r,
		Generated: r.StartedAt.Format(time.RFC1123),
		Elapsed:   r.Elapsed.Round(time.Millisecond).String(),
		Counts:    r.Counts(),
		Order:     Severities,
		Worst:     r.Worst(),
	})
}

type htmlView struct {
	Report
	Generated string
	Elapsed   string
	Counts    map[model.Severity]int
	Order     []model.Severity
	Worst     model.Severity
}

// HostName is the device name for a host, or empty when the passive registry
// has never seen it — the template renders those two cases differently.
func (v htmlView) HostName(h model.Host) string {
	if n, ok := v.Named(h.IP); ok {
		return n
	}
	return ""
}

// OpenOn lists just the open services of a host, for the inventory table.
func (v htmlView) OpenOn(h model.Host) []model.Service {
	var out []model.Service
	for _, s := range h.Services {
		if s.State == model.StateOpen {
			out = append(out, s)
		}
	}
	return out
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	// html/template will not interpolate a named string type into an attribute,
	// so severities cross into the page as plain strings.
	"sev":   func(s model.Severity) string { return string(s) },
	"upper": func(s model.Severity) string { return strings.ToUpper(string(s)) },
	"label": serviceLabel,
	"tls": func(s model.Service) string {
		if s.TLS == nil {
			return ""
		}
		parts := []string{s.TLS.Version}
		if s.TLS.Expired {
			parts = append(parts, "cert expired "+s.TLS.NotAfter)
		} else if s.TLS.SelfSigned {
			parts = append(parts, "self-signed")
		}
		if s.TLS.Subject != "" {
			parts = append(parts, s.TLS.Subject)
		}
		return strings.Join(parts, " · ")
	},
}).Parse(reportHTML))

const reportHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>stik-net audit — {{.Scope.Source}}</title>
<style>
:root {
  --bg: #ffffff; --fg: #16181d; --muted: #5c6370; --line: #e3e6ea; --card: #f7f8fa;
  --critical: #7b1020; --high: #c02339; --medium: #b06a00; --low: #2b6ea8; --info: #5c6370;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e8eaed; --muted: #9aa1ac; --line: #2a2e36; --card: #1b1e24;
    --critical: #ff7a90; --high: #ff8095; --medium: #f0b64a; --low: #74b8ea; --info: #9aa1ac;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.05rem; margin: 2.5rem 0 .75rem; padding-bottom: .35rem; border-bottom: 1px solid var(--line); }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .87em; }
.sub { color: var(--muted); margin: 0 0 1.5rem; }
.scope { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  padding: .85rem 1rem; margin-bottom: 1.5rem; }
.scope div { color: var(--muted); }
.scope .ranges { color: var(--fg); margin-top: .35rem; }
.score { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: .5rem; }
.chip { border: 1px solid currentColor; border-radius: 999px; padding: .2rem .7rem;
  font-size: .8rem; font-weight: 600; letter-spacing: .02em; }
.clean { color: #2e7d4f; font-weight: 600; }
.finding { border: 1px solid var(--line); border-left: 4px solid currentColor;
  border-radius: 6px; background: var(--card); padding: .9rem 1.1rem; margin: .8rem 0; }
.finding h3 { margin: 0 0 .3rem; font-size: 1rem; color: var(--fg); }
.finding .where { color: var(--muted); font-size: .85rem; margin-bottom: .5rem; }
.finding p { margin: .4rem 0; color: var(--fg); }
.finding .ev { background: var(--bg); border: 1px solid var(--line); border-radius: 4px;
  padding: .4rem .6rem; display: block; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.finding .fix { color: var(--muted); }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
.sev-medium { color: var(--medium); } .sev-low { color: var(--low); } .sev-info { color: var(--info); }
table { width: 100%; border-collapse: collapse; margin-top: .4rem; }
th, td { text-align: left; padding: .35rem .6rem .35rem 0; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
.host { margin-top: 1.4rem; }
.host .name { color: var(--muted); }
footer { color: var(--muted); font-size: .8rem; margin-top: 3rem; border-top: 1px solid var(--line); padding-top: 1rem; }
</style>
</head>
<body>
<main>
  <h1>Network audit</h1>
  <p class="sub">{{.Generated}} · {{len .Hosts}} host(s) up · {{.OpenServices}} open service(s) · scan took {{.Elapsed}}</p>

  <div class="scope">
    <div>Authorized scope · <span class="mono">{{.Scope.Source}}</span> · fingerprint <span class="mono">{{.Scope.Fingerprint}}</span></div>
    <div class="ranges mono">{{range .Scope.Entries}}{{.}} {{end}}</div>
  </div>

  <div class="score">
    {{- range $sev := .Order}}
      {{- $n := index $.Counts $sev}}
      {{- if $n}}<span class="chip sev-{{sev $sev}}">{{$n}} {{$sev}}</span>{{end}}
    {{- end}}
    {{- if not .Findings}}<span class="clean">Clean — no rule fired on anything reachable.</span>{{end}}
  </div>

  {{if .Findings}}
  <h2>Findings</h2>
  {{range .Findings}}
  <article class="finding sev-{{sev .Severity}}">
    <h3>{{.Title}}</h3>
    <div class="where">{{upper .Severity}} · {{$.Name .Host}}{{if ne ($.Name .Host) .Host}} ({{.Host}}){{end}}{{if .Port}} · {{.Port}}/tcp{{end}} · <span class="mono">{{.ID}}</span></div>
    <p>{{.Detail}}</p>
    {{if .Evidence}}<code class="ev">{{.Evidence}}</code>{{end}}
    {{if .Fix}}<p class="fix"><strong>Fix:</strong> {{.Fix}}</p>{{end}}
  </article>
  {{end}}
  {{end}}

  <h2>What's reachable</h2>
  {{range $h := .Hosts}}
  <div class="host">
    <strong class="mono">{{$h.IP}}</strong> <span class="name">{{$.HostName $h}}</span>
    {{with $.OpenOn $h}}
    <table>
      <tr><th>Port</th><th>Service</th><th>TLS</th><th>Banner</th></tr>
      {{range .}}
      <tr>
        <td class="mono">{{.Port}}/tcp</td>
        <td>{{label .}}</td>
        <td>{{tls .}}</td>
        <td class="mono">{{.Banner}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <div class="name">no open ports</div>
    {{end}}
  </div>
  {{end}}

  <footer>
    Generated by stik-net {{.Version}}. Findings describe what the scan observed — open ports, banners,
    certificates. Nothing here was authenticated to or exploited, and no vulnerability was confirmed.
  </footer>
</main>
</body>
</html>
`
