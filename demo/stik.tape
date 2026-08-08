# Reproducible README demo. Record with:  bash demo/record.sh
# (or, if stik is already built and on PATH:  vhs demo/stik.tape)

Output demo/stik.gif

Set Shell "bash"
Set FontSize 20
Set Width 1120
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"

# --- hidden setup: scratch registry with a fictional baseline ---
Hide
Type "export STIK_HOME=$(mktemp -d)" Enter
Type "export PATH=$PWD:$PATH" Enter
Type "bash demo/seed.sh" Enter
Type "clear" Enter
Show

# The everyday check: is anything new? Usually, no — and that's the point.
Type "stik-net" Sleep 600ms Enter
Sleep 2.5s

# Who's on the network, in plain terms.
Type "stik-net devices" Sleep 600ms Enter
Sleep 3s

Type "clear" Enter

# ...a little later, something new joins the Wi-Fi.
Type "# a new gadget connects to your network..." Sleep 400ms Enter
Type "bash demo/join.sh" Sleep 400ms Enter
Sleep 1.5s

# The money shot: stik noticed, and tells you in one line.
Type "stik-net" Sleep 600ms Enter
Sleep 3.5s

# It's just the new smart speaker. Give it a name.
Type 'stik-net name amazon "kitchen echo"' Sleep 600ms Enter
Sleep 2s

# Back to boring. Boring is the feature.
Type "stik-net" Sleep 600ms Enter
Sleep 3s
