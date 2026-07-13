#!/usr/bin/env bash
# Simulate a new, unrecognized device appearing on the network — exactly what
# the daemon records when it hears a MAC that isn't in the baseline.
set -euo pipefail
: "${STIK_HOME:?set STIK_HOME to a scratch dir}"

python3 - "$STIK_HOME/devices.json" <<'PY'
import json, sys, datetime
path = sys.argv[1]
data = json.load(open(path))
now = datetime.datetime.now(datetime.timezone.utc)
def iso(dt): return dt.isoformat().replace("+00:00", "Z")
joined = now - datetime.timedelta(minutes=2)
data["devices"].append({
    "mac":"fc:65:de:12:34:56","label":"Amazon device","vendor":"Amazon",
    "ip":"192.168.1.57","known":False,
    "first_seen":iso(joined),"last_seen":iso(now),
})
json.dump(data, open(path,"w"), indent=2)
PY
echo "(a device just connected — the daemon would catch this)"
