# Tattletale

Tattletale tells you what's going on behind your back on macOS: who asked for your
passwords, what opened a port, what new program ran, and what changed at login. Read-only,
no dependencies, with a local dashboard.

> **Beta, version 0.0.2.** It works and is tested on macOS, but expect rough edges and
> changes to the data format.

## Two versions, one dashboard

Tattletale comes in two versions that do exactly the same job. Pick whichever runtime you
already have:

| Version | Run it with | Needs |
|---|---|---|
| **Python** (`python/`) | `python3 python/tattletale.py` | Python 3.9 or newer; nothing to install |
| **Java** (`java/`) | `java -jar java/build/tattletale.jar`, or the native binary `java/build/tattletale` | JDK 25 to build; GraalVM to build the native binary, which then needs nothing |

Both write the same database, the same log and the same dashboard data into `data/`, so you
can switch between them and keep your history. Only one may run at a time: each refuses to
start while the other holds `data/tattletale.pid`. The format both follow is written down in
[docs/DATA_FORMAT.md](docs/DATA_FORMAT.md).

```
dashboard/   the one page, tattletale.html
python/      the Python watcher and its login-agent scripts
java/        the Java watcher, build.sh and its login-agent scripts (see java/README.md)
docs/        the data format and the demo recording
data/        created on first run: database, log, dashboard copy (git-ignored)
```

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

Everything Tattletale records stays in `data/` on your Mac: a SQLite database, a log, the
dashboard's data file and copies of your startup files. These contain your process list,
command lines and file contents, so **the whole folder is git-ignored**. Never commit it, and
look before you share a screenshot of the dashboard.

## Quick start

See [QUICKSTART.md](QUICKSTART.md). In short, from the repository folder:

```sh
python3 python/tattletale.py
```

or `sh java/build.sh` once and then `java -jar java/build/tattletale.jar`. Then open
`data/tattletale.html` in a browser.

## The dashboard

`dashboard/tattletale.html` is a single local page with no external resources. The watcher
copies it into `data/` on start, next to `tattletale-data.js`, which it rewrites about once a
minute; the page refreshes itself every 60 seconds. It shows:

- **Needs attention**: exposed ports, unsigned or ad-hoc programs, new programs,
  credential prompts, startup changes and watcher restarts, each linking to its details
- summary tiles, listening ports, credential prompts with their process chains
- new programs over time, who signed your programs, startup items
- the recent event log (filterable) and a searchable, sortable table of every program

It opens in dark mode; the Theme button switches to light and the page remembers your choice. It
works at phone width too. Click or press Enter on any row for its details. The footer names the
version that wrote the data.

## Command line

The same flags work for both versions; replace `python3 python/tattletale.py` with
`java -jar java/build/tattletale.jar` (or `java/build/tattletale`) for Java.

```sh
python3 python/tattletale.py                  # run the watcher (Ctrl-C to stop)
python3 python/tattletale.py --report         # summary of what has been recorded
python3 python/tattletale.py --show-settings  # every setting, its value and where it came from
python3 python/tattletale.py --version        # prints the version (this is 0.0.2)
python3 python/tattletale.py --query "SELECT exe, signer FROM programs WHERE signer = 'adhoc'"
```

`--query` opens the database read-only and accepts a single `SELECT` or `WITH` statement.

## Settings

Each setting has one name, usable three ways. Highest priority first:

1. a command-line flag: `--keep-logs 5`
2. an environment variable: `TATTLETALE_KEEP_LOGS=5`
3. a line in `tattletale.env` at the repository root (or `--config PATH`):
   `TATTLETALE_KEEP_LOGS=5`

Copy [`tattletale.env.example`](tattletale.env.example) to `tattletale.env` to start; both
versions read the same file. Unknown names and malformed values are refused with a message, not
ignored.

| Setting | Default | Meaning |
|---|---|---|
| `db` | `data/tattletale.db` | SQLite database; the dashboard data file and `startup-snapshots/` are written beside it |
| `log` | `data/tattletale.log` | human-readable log |
| `map` | `data/tattletale-map.json` | only read once, to import a JSON map from an older version |
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
sh python/install-login-agent.sh --dry-run    # see the LaunchAgent it would install
sh python/install-login-agent.sh              # install for your user and start it
sh python/uninstall-login-agent.sh            # stop and remove it (your data is kept)
```

For Java use `java/install-login-agent.sh` and `java/uninstall-login-agent.sh` (they run the
native binary when it is built, else the jar). Both versions install the same agent label,
so installing one replaces the other. Tattletale will report its own new agent as a startup
change, which is the point.

## Data model

SQLite (`data/tattletale.db`, WAL mode). Tables: `programs` (one row per executable, with
identity), `sightings` (each new process instance), `listeners` (with exposed and present
flags), `credential_events`, `startup_items` and `startup_versions`, `events` (every log
line) and `schema_version`. History is trimmed by the retention settings; programs,
listeners and startup items are kept. The full contract, column by column, is
[docs/DATA_FORMAT.md](docs/DATA_FORMAT.md).

## Upgrading from 0.0.1

0.0.1 kept its data next to `tattletale.py` at the repository root. On the first start with
default paths, either version moves that data into `data/` once (database, log, startup
copies) and says so; it refuses while a 0.0.1 watcher is still running against it.

**If you installed the 0.0.1 login agent, re-install it after upgrading.** The 0.0.1 agent runs
`tattletale.py` at the repository root, which 0.0.2 moved into `python/`, so it would keep
restarting a missing script and record nothing. Install the new one; it has the same label,
so the installer stops the old agent and replaces it:

```sh
sh python/install-login-agent.sh        # or java/install-login-agent.sh
```

Also fixed
in 0.0.2: `tattletale.env` was refused line by line in 0.0.1 (flags and environment variables
always worked), and the Python watcher left its `log stream` helper running after it stopped.

## Requirements

- **macOS.** Tested on macOS 27.0.1 on Apple silicon. Other versions have not been tested
  yet; reports are welcome. It should work on any recent macOS that has the tools below.
- **Python version:** Python 3.9 or newer. The `python3` from Apple's Command Line Tools is
  fine (`xcode-select --install` if `python3` is missing). No packages to install.
- **Java version:** a JDK 25 to build and run the jar; GraalVM 25 (`GRAALVM_HOME`) to build
  the native binary, which then runs on its own. No third-party libraries. It uses macOS's
  built-in `/usr/bin/sqlite3`.
- **Built-in macOS tools** both run: `ps`, `lsof`, `codesign`, `crontab`, `osascript` (for
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

Recorded with [BrewShot](https://github.com/supsup/BrewShot), a zero-dependency Java
screenshot tool that drives headless Chrome and brews a GIF straight from a page:

```sh
java -jar brewshot.jar tattletale.html -o tattletale-demo.gif --size 1000x640 --gif 70 --gif-delay 200
```

Thanks, BrewShot. ☕
