#!/usr/bin/env bash
# Seed a demo registry with a small, fictional baseline so the README GIF is
# reproducible and doesn't leak anyone's real device names.
set -euo pipefail
: "${STIK_HOME:?set STIK_HOME to a scratch dir}"
mkdir -p "$STIK_HOME"

python3 - "$STIK_HOME/devices.json" <<'PY'
import json, sys, datetime
now = datetime.datetime(2026, 7, 12, 14, 30, tzinfo=datetime.timezone.utc)
def iso(dt): return dt.isoformat().replace("+00:00", "Z")
days = datetime.timedelta(days=1)
mins = datetime.timedelta(minutes=1)
devices = [
    {"mac":"a4:83:e7:11:22:33","name":"my phone","label":"Apple iPhone","vendor":"Apple",
     "hostname":"dylans-iphone","ip":"192.168.1.20","known":True,
     "first_seen":iso(now-30*days),"last_seen":iso(now-2*mins)},
    {"mac":"3c:07:54:44:55:66","name":"living room TV","label":"Apple TV","vendor":"Apple",
     "hostname":"apple-tv","ip":"192.168.1.24","known":True,
     "first_seen":iso(now-30*days),"last_seen":iso(now-mins)},
    {"mac":"f0:18:98:77:88:99","name":"work laptop","label":"Apple MacBook","vendor":"Apple",
     "hostname":"dylans-macbook","ip":"192.168.1.31","known":True,
     "first_seen":iso(now-30*days),"last_seen":iso(now-4*mins)},
    {"mac":"d8:31:34:aa:bb:cc","name":"the router","label":"TP-Link device","vendor":"TP-Link",
     "ip":"192.168.1.1","known":True,
     "first_seen":iso(now-30*days),"last_seen":iso(now)},
]
json.dump({"version":1,"devices":devices}, open(sys.argv[1],"w"), indent=2)
PY
