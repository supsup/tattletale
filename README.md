# Tattletale

Tattletale tells you what's going on behind your back on macOS: who asked for your
passwords, what opened a port, what new program ran, and what changed at login. Read-only,
no dependencies, with a local dashboard.

> **Beta, version 0.0.1.** It works and is tested on macOS with Python 3.9, but expect rough
> edges and changes to the data format.

## What it watches

| Check | How often | What you learn |
|---|---|---|
| **Credential prompts** | every 3 s, plus the macOS log | Every time a git credential helper, `git-remote-https`, the macOS password dialog (SecurityAgent) or an askpass helper runs, with its command line and the chain of processes that started it. Short-lived helpers are caught from the macOS unified log and looked up immediately, so "something asked for my GitHub password" becomes "`git-remote-https https://github.com/example/private-repo` started by `git` started by `your-build-tool`". |
| **Listening ports** | every 30 s | Each new program, address and port that accepts connections. A listener on all interfaces (`*`, `0.0.0.0`, `::`) is flagged as **exposed**: reachable from other machines on your network. Ports that stop listening are noted too. |
| **New programs** | every 3 s | Every executable that runs for the first time, busy or not, with its full path, command line, parent chain, SHA-256 and code-signing identity (Apple, a named developer, ad-hoc or unsigned). |
| **Startup items** | every 5 min | Launch agents and daemons, crontab and shell startup files. Any addition, change or removal is logged, with a copy of the before and after versions and a diff. |

The first run records what is already there as a **baseline** and reports only what changes
after it.

## What it does not do

- It never blocks, kills or changes anything. It only reads (`ps`, `lsof`, `codesign`,
  `log stream`, `crontab -l`, file reads) and writes its own files.
- It does not send anything anywhere. There is no network code.
- It does not need root. Some things are invisible without it: other users' listening ports,
  and system launch items you cannot read.
- A process that starts and exits within one scan (about 3 seconds) can be missed by the
  process check. Credential and git network helpers are also caught from the macOS log for
  exactly this reason; other short-lived programs may not be.

## Privacy

Everything Tattletale records stays in its folder on your Mac: a SQLite database, a log, the
dashboard's data file and copies of your startup files. These contain your process list,
command lines and file contents, so **all of them are git-ignored**. Never commit them, and
look before you share a screenshot of the dashboard.

## Quick start

See [QUICKSTART.md](QUICKSTART.md). In short:

```sh
python3 tattletale.py
```

then open `tattletale.html` in a browser.

## The dashboard

`tattletale.html` is a single local page with no external resources. It loads
`tattletale-data.js`, which the watcher rewrites about once a minute, and refreshes itself
every 60 seconds. It shows:

- **Needs attention**: exposed ports, unsigned or ad-hoc programs, new programs,
  credential prompts, startup changes and watcher restarts, each linking to its details
- summary tiles, listening ports, credential prompts with their process chains
- new programs over time, who signed your programs, startup items
- the recent event log (filterable) and a searchable, sortable table of every program

It opens in dark mode; the Theme button switches to light and the page remembers your choice. It
works at phone width too. Click or press Enter on any row for its details.

## Command line

```sh
python3 tattletale.py                  # run the watcher (Ctrl-C to stop)
python3 tattletale.py --report         # summary of what has been recorded
python3 tattletale.py --show-settings  # every setting, its value and where it came from
python3 tattletale.py --version        # prints the version (this is 0.0.1)
python3 tattletale.py --query "SELECT exe, signer FROM programs WHERE signer = 'adhoc'"
```

`--query` opens the database read-only and accepts a single `SELECT` or `WITH` statement.

## Settings

Each setting has one name, usable three ways. Highest priority first:

1. a command-line flag: `--keep-logs 5`
2. an environment variable: `TATTLETALE_KEEP_LOGS=5`
3. a line in `tattletale.env` next to `tattletale.py` (or `--config PATH`):
   `TATTLETALE_KEEP_LOGS=5`

Copy [`tattletale.env.example`](tattletale.env.example) to `tattletale.env` to start.
Unknown names and malformed values are refused with a message, not ignored.

| Setting | Default | Meaning |
|---|---|---|
| `db` | `tattletale.db` next to the script | SQLite database; the dashboard data file and `startup-snapshots/` are written beside it |
| `log` | `tattletale.log` next to the script | human-readable log |
| `map` | `tattletale-map.json` | only read once, to import a JSON map from an older version |
| `process_interval` | `3` | seconds between process-list scans |
| `listen_interval` | `30` | seconds between listening-port scans |
| `startup_interval` | `300` | seconds between startup-item scans |
| `notify` | `true` | macOS notifications for alerts, at most one per kind per minute |
| `rotate_mb` | `20` | rotate the log at this size |
| `keep_logs` | `3` | how many rotated logs to keep |
| `retention_days` | `30` | days of events and credential events to keep (0 = forever) |
| `sightings_retention_days` | `7` | days of process sightings to keep, the busiest table (0 = forever) |
| `extra_startup` | none | extra files to watch as startup items (colon-separated in env and config) |

## Notifications

When something needs attention, Tattletale shows a macOS notification: a credential prompt,
a git network credential lookup, a password dialog, a newly exposed port, a startup change,
or a new program with no named signer. The first one may ask macOS for permission to show
notifications. Turn them off with `--no-notify` or `TATTLETALE_NOTIFY=false`.

## Run at login (optional)

```sh
sh install-login-agent.sh --dry-run    # see the LaunchAgent it would install
sh install-login-agent.sh              # install for your user and start it
sh uninstall-login-agent.sh            # stop and remove it (your data is kept)
```

The agent runs `tattletale.py` from this folder with your `tattletale.env`. Tattletale will
report its own new agent as a startup change, which is the point.

## Data model

SQLite (`tattletale.db`, WAL mode). Tables: `programs` (one row per executable, with
identity), `sightings` (each new process instance), `listeners` (with exposed and present
flags), `credential_events`, `startup_items` and `startup_versions`, `events` (every log
line) and `schema_version`. History is trimmed by the retention settings; programs,
listeners and startup items are kept.

## Requirements

- **macOS.** Tested on macOS 27.0.1 on Apple silicon. Other versions have not been tested
  yet; reports are welcome. It should work on any recent macOS that has the tools below.
- **Python 3.9 or newer.** The `python3` from Apple's Command Line Tools is fine (`xcode-select
  --install` if `python3` is missing). No packages to install.
- **Built-in macOS tools** it runs: `ps`, `lsof`, `codesign`, `crontab`, `osascript` (for
  notifications) and `log stream --style ndjson` (for catching short-lived credential
  helpers).

If `log stream` cannot run with that style, Tattletale writes one `NOTE` line to its log and
watches credential helpers through the process list alone, which can miss a helper that starts
and exits within one scan. Everything else works the same. Intel Macs have not been tested
either.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## What it looks like

![The Tattletale dashboard in dark mode, scrolling from Needs attention through listening ports, credential prompts, signers, startup items, the event log and the program table](docs/tattletale-demo.gif)

The recording uses demo data: real macOS system programs, with the user renamed and a few
invented events (an unsigned download, an exposed dev server, a password dialog, a startup
change) so that every section has something in it.
