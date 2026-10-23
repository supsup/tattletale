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
2026-01-15T09:00:00Z  START     tattletale 0.0.2 pid 4242 db /path/to/tattletale/data/tattletale.db
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

Listener labels describe **bind scope**: loopback, wildcard, non-loopback or unknown.
For example, `127.0.0.1` is loopback and `192.0.2.10` is a non-loopback literal. These labels
do not test firewall rules or access from another machine. The older `EXPOSED` log label
means wildcard binding, not demonstrated reachability.

The four health checks follow the existing polling schedule; no automatic retry is added.
They do not cover every watcher component. More detail, including startup/crontab rejection
and accepted-empty results, is in [the data contract](docs/DATA_FORMAT.md#collection-health).

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
