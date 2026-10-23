#!/bin/sh
# Opt-in: run tattletale at login, for this user only, as a LaunchAgent.
#   sh install-login-agent.sh            install and start it now
#   sh install-login-agent.sh --dry-run  print the agent file, change nothing
# Remove it with uninstall-login-agent.sh. Settings come from tattletale.env next to
# tattletale.py, exactly as when you run it by hand.
set -eu
here=$(cd "$(dirname "$0")" && pwd) || { echo "install-login-agent: cannot locate this folder" >&2; exit 2; }
label="io.github.tattletale"
plist="$HOME/Library/LaunchAgents/$label.plist"
python=$(command -v python3) || { echo "install-login-agent: python3 not found" >&2; exit 2; }

xml_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
py=$(xml_escape "$python")
dir=$(xml_escape "$here")

body=$(cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$py</string>
    <string>-I</string>
    <string>$dir/tattletale.py</string>
  </array>
  <key>WorkingDirectory</key><string>$dir</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$dir/tattletale.stdout</string>
  <key>StandardErrorPath</key><string>$dir/tattletale.stdout</string>
</dict>
</plist>
EOF
)

if [ "${1:-}" = "--dry-run" ]; then
    echo "would write $plist:"
    printf '%s\n' "$body"
    exit 0
fi

if [ -f "$here/tattletale.pid" ] && kill -0 "$(cat "$here/tattletale.pid")" 2>/dev/null; then
    echo "install-login-agent: a tattletale started by hand is running (pid $(cat "$here/tattletale.pid")); stop it first:" >&2
    echo "  kill \$(cat \"$here/tattletale.pid\")" >&2
    exit 1
fi

mkdir -p "$HOME/Library/LaunchAgents"
tmp=$(mktemp "$plist.XXXXXX")
printf '%s\n' "$body" > "$tmp"
plutil -lint "$tmp" >/dev/null || { rm -f "$tmp"; echo "install-login-agent: generated plist is invalid" >&2; exit 2; }
mv "$tmp" "$plist"
launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$plist"
echo "installed $plist and started it; it now runs at every login."
echo "status: launchctl print gui/$(id -u)/$label | head"
