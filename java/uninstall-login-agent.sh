#!/bin/sh
# Stop tattletale's login agent and remove it. Your log, database and snapshots are kept.
# The label io.github.tattletale is shared with python/uninstall-login-agent.sh: this removes
# the login agent whichever version (Java or Python) it runs.
set -eu
label="io.github.tattletale"
plist="$HOME/Library/LaunchAgents/$label.plist"
if [ "${1:-}" = "--dry-run" ]; then
    echo "would stop gui/$(id -u)/$label and remove $plist"
    exit 0
fi
launchctl bootout "gui/$(id -u)/$label" 2>/dev/null && echo "stopped $label" || echo "$label was not running"
if [ -f "$plist" ]; then rm "$plist" && echo "removed $plist"; else echo "no agent file at $plist"; fi
