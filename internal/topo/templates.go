package topo

// mapFragment is the embeddable map: markup, scoped CSS and an inline script.
// No external asset, no library — a report has to open correctly on a laptop
// with no network, which rules out a CDN even for something as ordinary as a
// force-directed layout.
const mapFragment = `
<section class="stik-map">
  <div class="stik-map-grid">
    <div class="stik-map-canvas-wrap">
      <canvas id="stik-map-canvas" width="720" height="420" aria-label="Network map"></canvas>
    </div>
    <aside class="stik-map-panel" id="stik-map-panel">
      <p class="stik-map-hint">Click a node to see what's on it.</p>
    </aside>
  </div>
  <div class="stik-map-legend">
    <span><i class="dot sev-critical"></i>critical</span>
    <span><i class="dot sev-high"></i>high</span>
    <span><i class="dot sev-medium"></i>medium</span>
    <span><i class="dot sev-low"></i>low</span>
    <span><i class="dot sev-none"></i>no findings</span>
    <span class="rule"><i class="line solid"></i>observed</span>
    <span class="rule"><i class="line dashed"></i>inferred{{if .Inferred}} ({{.Inferred}}){{end}}</span>
  </div>
  <ul class="stik-map-fallback" id="stik-map-fallback">
    {{range .Nodes}}<li><strong>{{.ID}}</strong> {{.Label}} <em>{{.Kind}}</em>{{if .Open}} · {{.Open}} open{{end}}</li>
    {{end}}
  </ul>
</section>
<style>
.stik-map { margin: .5rem 0 1rem; }
.stik-map-grid { display: grid; grid-template-columns: minmax(0, 2fr) minmax(14rem, 1fr); gap: 1rem; align-items: start; }
@media (max-width: 44rem) { .stik-map-grid { grid-template-columns: 1fr; } }
.stik-map-canvas-wrap { border: 1px solid var(--line, #ddd); border-radius: 8px; background: var(--card, #f7f8fa); overflow: hidden; }
#stik-map-canvas { display: block; width: 100%; height: auto; touch-action: none; cursor: grab; }
.stik-map-panel { border: 1px solid var(--line, #ddd); border-radius: 8px; padding: .75rem .9rem; background: var(--card, #f7f8fa); font-size: .85rem; min-height: 8rem; }
.stik-map-panel h4 { margin: 0 0 .2rem; font-size: .95rem; }
.stik-map-panel .meta { color: var(--muted, #666); margin-bottom: .5rem; }
.stik-map-panel ul { margin: .3rem 0 .6rem; padding-left: 1.1rem; }
.stik-map-panel li { margin: .1rem 0; }
.stik-map-hint { color: var(--muted, #666); margin: 0; }
.stik-map-legend { display: flex; flex-wrap: wrap; gap: .75rem; margin-top: .6rem; font-size: .78rem; color: var(--muted, #666); }
.stik-map-legend i.dot { display: inline-block; width: .6rem; height: .6rem; border-radius: 50%; margin-right: .3rem; vertical-align: middle; }
.stik-map-legend i.line { display: inline-block; width: 1.1rem; height: 0; border-top: 2px solid currentColor; margin-right: .3rem; vertical-align: middle; }
.stik-map-legend i.line.dashed { border-top-style: dashed; }
.stik-map-legend .dot.sev-critical { background: #7b1020; }
.stik-map-legend .dot.sev-high { background: #c02339; }
.stik-map-legend .dot.sev-medium { background: #b06a00; }
.stik-map-legend .dot.sev-low { background: #2b6ea8; }
.stik-map-legend .dot.sev-none { background: #8a9099; }
.stik-map-fallback { font-size: .85rem; }
</style>
<script>
(function () {
  "use strict";
  var GRAPH = {{.Graph}};
  var DETAILS = {{.Details}};

  var canvas = document.getElementById("stik-map-canvas");
  var panel = document.getElementById("stik-map-panel");
  var fallback = document.getElementById("stik-map-fallback");
  if (!canvas || !canvas.getContext) { return; }   // no canvas: the list stays
  if (fallback) { fallback.style.display = "none"; }

  var ctx = canvas.getContext("2d");
  var W = canvas.width, H = canvas.height;
  var detailByID = {};
  DETAILS.forEach(function (d) { detailByID[d.id] = d; });

  // A seeded PRNG, so the same scan always lays out the same way. A map that
  // rearranges itself on every reload is a map you can't refer to.
  var seed = 20260821;
  function rand() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }

  var nodes = GRAPH.nodes.map(function (n, i) {
    return {
      id: n.id, kind: n.kind, label: n.label, sev: n.sev || "", open: n.open || 0,
      mac: n.mac || "", subnet: n.subnet || "",
      x: W / 2 + (rand() - 0.5) * W * 0.6, y: H / 2 + (rand() - 0.5) * H * 0.6,
      vx: 0, vy: 0, i: i
    };
  });
  var index = {};
  nodes.forEach(function (n) { index[n.id] = n; });
  var edges = (GRAPH.edges || []).map(function (e) {
    return { a: index[e.from], b: index[e.to], inferred: !!e.inferred, evidence: e.evidence };
  }).filter(function (e) { return e.a && e.b; });

  // Fruchterman-Reingold: repulsion between every pair, springs along edges,
  // cooling schedule. Small graphs, so an O(n²) pass is free.
  var k = Math.sqrt((W * H) / Math.max(nodes.length, 1)) * 0.55;
  function layout(steps) {
    var temp = W / 8;
    for (var s = 0; s < steps; s++) {
      for (var i = 0; i < nodes.length; i++) {
        var a = nodes[i]; a.vx = 0; a.vy = 0;
        for (var j = 0; j < nodes.length; j++) {
          if (i === j) continue;
          var b = nodes[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var d = Math.sqrt(dx * dx + dy * dy) || 0.01;
          var rep = (k * k) / d;
          a.vx += (dx / d) * rep; a.vy += (dy / d) * rep;
        }
        // Gravity toward the middle keeps disconnected pieces on screen.
        a.vx += (W / 2 - a.x) * 0.012;
        a.vy += (H / 2 - a.y) * 0.012;
      }
      edges.forEach(function (e) {
        var dx = e.a.x - e.b.x, dy = e.a.y - e.b.y;
        var d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        var att = (d * d) / k;
        var fx = (dx / d) * att, fy = (dy / d) * att;
        e.a.vx -= fx; e.a.vy -= fy;
        e.b.vx += fx; e.b.vy += fy;
      });
      nodes.forEach(function (n) {
        if (n.pinned) return;
        var sp = Math.sqrt(n.vx * n.vx + n.vy * n.vy) || 0.01;
        var lim = Math.min(sp, temp);
        n.x += (n.vx / sp) * lim;
        n.y += (n.vy / sp) * lim;
        n.x = Math.max(24, Math.min(W - 24, n.x));
        n.y = Math.max(24, Math.min(H - 24, n.y));
      });
      temp *= 0.94;
    }
  }

  function dark() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  function sevColor(sev) {
    var light = { critical: "#7b1020", high: "#c02339", medium: "#b06a00", low: "#2b6ea8" };
    var night = { critical: "#ff7a90", high: "#ff8095", medium: "#f0b64a", low: "#74b8ea" };
    var table = dark() ? night : light;
    return table[sev] || (dark() ? "#8b929c" : "#8a9099");
  }
  function ink() { return dark() ? "#e8eaed" : "#16181d"; }
  function faint() { return dark() ? "#3a3f48" : "#c9ced6"; }

  function radius(n) {
    if (n.kind === "subnet") return 9;
    return 6 + Math.min(n.open, 12) * 0.9;
  }

  var selected = null;

  function draw() {
    var dpr = window.devicePixelRatio || 1;
    canvas.width = W * dpr; canvas.height = H * dpr;
    canvas.style.height = (H * (canvas.clientWidth / W)) + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    edges.forEach(function (e) {
      ctx.beginPath();
      ctx.strokeStyle = faint();
      ctx.lineWidth = e.inferred ? 1 : 1.6;
      ctx.setLineDash(e.inferred ? [4, 4] : []);
      ctx.moveTo(e.a.x, e.a.y);
      ctx.lineTo(e.b.x, e.b.y);
      ctx.stroke();
    });
    ctx.setLineDash([]);

    nodes.forEach(function (n) {
      var r = radius(n);
      ctx.beginPath();
      if (n.kind === "subnet") {
        ctx.rect(n.x - r, n.y - r * 0.7, r * 2, r * 1.4);
      } else {
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      }
      ctx.fillStyle = n.kind === "subnet" ? faint() : sevColor(n.sev);
      ctx.fill();
      if (n.kind === "gateway" || n.kind === "this-host" || n === selected) {
        ctx.lineWidth = n === selected ? 3 : 2;
        ctx.strokeStyle = ink();
        ctx.stroke();
      }
      ctx.fillStyle = ink();
      ctx.font = (n.kind === "subnet" ? "600 11px " : "11px ") +
        "ui-monospace, SFMono-Regular, Menlo, monospace";
      ctx.textAlign = "center";
      var caption = n.label;
      if (caption.length > 22) { caption = caption.slice(0, 21) + "…"; }
      ctx.fillText(caption, n.x, n.y + r + 12);
      if (n.kind === "this-host") { ctx.fillText("you are here", n.x, n.y + r + 24); }
    });
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function show(n) {
    selected = n;
    if (!n) {
      panel.innerHTML = '<p class="stik-map-hint">Click a node to see what&#39;s on it.</p>';
      draw();
      return;
    }
    var d = detailByID[n.id] || {};
    var html = "<h4>" + esc(n.label) + "</h4>";
    var meta = [n.id];
    if (n.kind !== "host") { meta.push(n.kind.replace("-", " ")); }
    if (n.mac) { meta.push(n.mac); }
    html += '<div class="meta">' + esc(meta.join(" · ")) + "</div>";

    if (d.services && d.services.length) {
      html += "<strong>Open</strong><ul>";
      d.services.forEach(function (s) { html += "<li>" + esc(s) + "</li>"; });
      html += "</ul>";
    } else if (n.kind !== "subnet") {
      html += '<div class="meta">no open ports</div>';
    }

    if (d.findings && d.findings.length) {
      html += "<strong>Findings</strong><ul>";
      d.findings.forEach(function (f) {
        var where = f.port ? " (" + f.port + "/tcp)" : "";
        html += "<li>" + esc(f.severity.toUpperCase()) + " — " + esc(f.title) + esc(where) + "</li>";
      });
      html += "</ul>";
    }
    panel.innerHTML = html;
    draw();
  }

  function at(ev) {
    var rect = canvas.getBoundingClientRect();
    var scale = W / rect.width;
    var x = (ev.clientX - rect.left) * scale, y = (ev.clientY - rect.top) * scale;
    var hit = null;
    nodes.forEach(function (n) {
      var dx = n.x - x, dy = n.y - y;
      if (Math.sqrt(dx * dx + dy * dy) <= radius(n) + 6) { hit = n; }
    });
    return { node: hit, x: x, y: y };
  }

  var dragging = null;
  canvas.addEventListener("pointerdown", function (ev) {
    var h = at(ev);
    if (h.node) {
      dragging = h.node; dragging.pinned = true;
      canvas.setPointerCapture(ev.pointerId);
      canvas.style.cursor = "grabbing";
    }
    show(h.node);
  });
  canvas.addEventListener("pointermove", function (ev) {
    if (!dragging) return;
    var h = at(ev);
    dragging.x = h.x; dragging.y = h.y;
    draw();
  });
  canvas.addEventListener("pointerup", function () {
    dragging = null; canvas.style.cursor = "grab";
  });
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (mq.addEventListener) { mq.addEventListener("change", draw); }
  }
  window.addEventListener("resize", draw);

  layout(400);
  draw();
})();
</script>
`

// mapPage wraps the fragment for `stik-net topo --out map.html`.
const mapPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root { --bg: #ffffff; --fg: #16181d; --muted: #5c6370; --line: #e3e6ea; --card: #f7f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14161a; --fg: #e8eaed; --muted: #9aa1ac; --line: #2a2e36; --card: #1b1e24; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem 3rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
p.sub { color: var(--muted); margin: 0 0 1.25rem; }
footer { color: var(--muted); font-size: .8rem; margin-top: 2rem; border-top: 1px solid var(--line); padding-top: 1rem; }
</style>
</head>
<body>
<main>
  <h1>{{.Title}}</h1>
  {{if .Subtitle}}<p class="sub">{{.Subtitle}}</p>{{end}}
  {{.Map}}
  <footer>
    Inferred structure, not observed cabling. Solid links are relationships stik-net watched happen;
    dashed links are reasoned from addressing.
  </footer>
</main>
</body>
</html>
`
