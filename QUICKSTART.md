# Tattletale quick start

Two minutes from clone to dashboard.

## 1. Get it

```sh
git clone https://github.com/supsup/tattletale.git
cd tattletale
python3 --version        # 3.9 or newer; Apple's Command Line Tools Python is fine
```

No packages to install.

## 2. Start the watcher

```sh
python3 tattletale.py
```

You will see something like:

```text
2026-01-15T09:00:00Z  START     tattletale 0.0.1 pid 4242 db /path/to/tattletale/tattletale.db
2026-01-15T09:00:01Z  BASELINE  programs: 512 recorded
2026-01-15T09:00:04Z  BASELINE  listeners: 18 recorded, 3 on all interfaces: ...
2026-01-15T09:00:04Z  BASELINE  startup items: 14 recorded, copies in .../startup-snapshots
```

The first run records what is already on your Mac as the baseline. From then on it reports
only changes, for example:

```text
2026-01-15T09:12:30Z  NEW-PROG  pid 5150 user alex /Applications/Example.app/Contents/MacOS/Example | ...
2026-01-15T09:12:31Z  IDENTITY  /Applications/Example.app/Contents/MacOS/Example | signer: Developer ID Application: Example Inc (ABCDE12345) ...
2026-01-15T09:20:02Z  CRED-NET  git-remote-http pid 6060 | args: .../git-remote-https https://github.com/example/private-repo ... | chain: git-remote-https(6060) <- git(6059) <- make(6001) <- zsh(500)
2026-01-15T09:25:00Z  LISTEN!   EXPOSED on all interfaces example-server pid 7070 listening on *:8000 ...
```

Leave it running in a terminal tab. Stop it with Ctrl-C.

## 3. Open the dashboard

Open `tattletale.html` from this folder in your browser (double-click it, or
`open tattletale.html`). It reloads its data every minute. Start with **Needs attention** at
the top.

## 4. Optional: settings

```sh
cp tattletale.env.example tattletale.env      # then edit; it is git-ignored
python3 tattletale.py --show-settings          # check what took effect
```

Common changes: `TATTLETALE_NOTIFY=false` to turn off notifications, or a longer
`TATTLETALE_PROCESS_INTERVAL` to use even less CPU.

## 5. Optional: run at login

```sh
sh install-login-agent.sh          # install and start; it now runs at every login
sh uninstall-login-agent.sh        # remove it again
```

## Ask it questions

```sh
python3 tattletale.py --report
python3 tattletale.py --query "SELECT time, exe, args, chain FROM credential_events ORDER BY time DESC LIMIT 10"
python3 tattletale.py --query "SELECT key FROM listeners WHERE exposed = 1 AND present = 1"
```

## Remove it

Stop the watcher (or run `sh uninstall-login-agent.sh`), then delete this folder. Tattletale
writes nothing outside it except the optional login agent in
`~/Library/LaunchAgents/io.github.tattletale.plist`.
