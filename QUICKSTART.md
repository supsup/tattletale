# Tattletale quick start

Two minutes from clone to dashboard. Pick the Python or the Java version; they do the same
job and share the same data folder.

## 1. Get it

```sh
git clone https://github.com/supsup/tattletale.git
cd tattletale
```

**Python:** `python3 --version` must be 3.9 or newer (Apple's Command Line Tools Python is
fine). Nothing to install.

**Java:** a JDK 25 on your PATH (or `JAVA_HOME`). Build once:

```sh
sh java/build.sh              # java/build/tattletale.jar, plus a native binary if GRAALVM_HOME is set
```

## 2. Start the watcher

From the repository folder:

```sh
python3 python/tattletale.py              # Python
java -jar java/build/tattletale.jar       # Java (or java/build/tattletale for the native binary)
```

You will see something like:

```text
2026-01-15T09:00:00Z  START     tattletale 0.0.3 pid 4242 db /path/to/tattletale/data/tattletale.db
2026-01-15T09:00:01Z  BASELINE  programs: 512 recorded
2026-01-15T09:00:04Z  BASELINE  listeners: 18 recorded, 3 on all interfaces: ...
2026-01-15T09:00:04Z  BASELINE  startup items: 14 recorded, copies in .../data/startup-snapshots
```

The first run records what is already on your Mac as the baseline. From then on it reports
only changes, for example:

```text
2026-01-15T09:12:30Z  NEW-PROG  pid 5150 user alex /Applications/Example.app/Contents/MacOS/Example | ...
2026-01-15T09:12:31Z  IDENTITY  /Applications/Example.app/Contents/MacOS/Example | signer: Developer ID Application: Example Inc (ABCDE12345) ...
2026-01-15T09:20:02Z  CRED-NET  git-remote-http pid 6060 | args: .../git-remote-https https://github.com/example/private-repo ... | chain: git-remote-https(6060) <- git(6059) <- make(6001) <- zsh(500)
2026-01-15T09:25:00Z  LISTEN!   EXPOSED on all interfaces example-server pid 7070 listening on *:8000 ...
```

Leave it running in a terminal tab. Stop it with Ctrl-C. Only one watcher runs at a time; a
second one (of either version) refuses and tells you which pid holds `data/`.

## 3. Open the dashboard

Open `data/tattletale.html` in your browser (`open data/tattletale.html`). The watcher puts
it there next to its data. It reloads every minute. Start with **Needs attention** at the top.

Check both kinds of status. **Live** means the data file is recent; it becomes **Stale**
after 180 seconds. Collection health separately reports processes, listeners, startup and
crontab as `unknown`, `ok` or `degraded`, with their attempt and accepted-success times.
Failed checks keep last-known values rather than reporting stopped listeners or removed
startup items. A new watcher starts with unknown health even when it loads old inventory;
legacy or unsupported health is unknown too. Live does not mean every check succeeded.
Degraded/unknown check names remain visible when the file becomes Stale. A failed refresh
keeps the last fully accepted values and update time under a last-known/load-error warning.

Also check **Database publication**. A recoverable save failure may write current collector
health beside older cached inventory, all labelled last-known. **Inventory as of** dates the
last complete database projection; Live/Stale dates the envelope, not that inventory.
Publication success advances only after a complete successful save. If replacement fails,
the old file remains; it cannot announce its own failed update. Missing new publication
fields in older format-2 data are supported, while malformed present fields are incomplete.

Listener labels describe **bind scope**: loopback, wildcard, non-loopback or unknown.
For example, `127.0.0.1` is loopback and `192.0.2.10` is a non-loopback literal. These labels
do not test firewall rules or access from another machine. The older `EXPOSED` log label
means wildcard binding, not demonstrated reachability.

Startup files and crontab are attempted independently on each startup cycle. A failure in
one retains its prior values while good peer changes can commit. Persistent unreadable
entry markers allow readable peers to be observed, but keep startup health degraded.
Known nonregular entries and regular files over 16 MiB are marked rather than read as
content; accepted files are hashed completely and saved copies keep at most 4 MiB.
Becoming unreadable and readable again is not a content change by itself; a new readable
version is compared with the last readable copy. If an item has never been readable, its
first readable content emits one `STARTUP~` with `before: None` and its saved after-copy.
Repeating that same readable content adds no change. Crontab must decode as UTF-8; another
encoding degrades that partition and retains its last-known values.
The four health checks follow the existing polling schedule; no automatic retry is added.
They do not cover every watcher component. More detail, including startup/crontab rejection
and accepted-empty results, is in [the data contract](docs/DATA_FORMAT.md#collection-health).

## Optional: watch it in a terminal

```sh
python3 python/tattletale.py --hud                   # in a second tab; Ctrl-C to quit
python3 python/tattletale.py --hud --hud-interval 5  # redraw every 5 s (default 10, minimum 2)
```

The HUD is read-only and Python-only (it reads the same `data/` folder whichever version
is watching). It shows whether the watcher is running, counts since its start, ports open
on all interfaces, recent new programs and credential events, and an ALERTS pane at the
bottom for alerts that arrived since the HUD started. To label rows you already know are
fine, copy `tattletale.hud-baseline.example` to `tattletale.hud-baseline` (git-ignored) and
edit it; matching rows say `known` instead of `ALERT`.

## 4. Optional: settings

```sh
cp tattletale.env.example tattletale.env       # at the repository root; git-ignored; both versions read it
python3 python/tattletale.py --show-settings   # check what took effect
```

Common changes: `TATTLETALE_NOTIFY=false` to turn off notifications, or a longer
`TATTLETALE_PROCESS_INTERVAL` to use even less CPU.

## 5. Optional: run at login

```sh
sh python/install-login-agent.sh      # Python: install and start; it now runs at every login
sh java/install-login-agent.sh        # or Java (uses the native binary when built)
sh python/uninstall-login-agent.sh    # remove it again (either uninstall script works)
```

## Ask it questions

```sh
python3 python/tattletale.py --report
python3 python/tattletale.py --query "SELECT time, exe, args, chain FROM credential_events ORDER BY time DESC LIMIT 10"
python3 python/tattletale.py --query "SELECT key FROM listeners WHERE exposed = 1 AND present = 1"
```

(The Java version takes the same flags.)

## Remove it

Stop the watcher (or run the uninstall script), then delete this folder. Tattletale writes
nothing outside it except the optional login agent in
`~/Library/LaunchAgents/io.github.tattletale.plist`.
