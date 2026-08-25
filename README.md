# redact

Redact IPs, hostnames, MAC addresses, emails and credentials from text
files (logs, configuration files, support bundles) before sharing them
publicly - opening a bug report, posting to a forum, or attaching output
to a support ticket.

No third-party dependencies. Pure Python 3 standard library.

## What it detects

| Type | Examples | Placeholder |
|---|---|---|
| IPv4 / IPv6 | `192.168.1.1`, `10.0.0.0/24`, `fe80::1a2b:3c4d`, `::1` | `[REDACTED-IP]` |
| Hostnames / FQDNs | `db.internal.corp`, `api.example.com` | `[REDACTED-HOSTNAME]` |
| MAC addresses | `00:1A:2B:3C:4D:5E` | `[REDACTED-MAC]` |
| Emails | `user@example.com` | `[REDACTED-EMAIL]` |
| Credentials | AWS keys, GitHub/Slack tokens, JWTs, `Bearer <token>`, PEM private keys, `password=`/`api_key:`/`secret=`/`token:` assignments | `[REDACTED-CREDENTIAL]` |

Redaction is fixed/simple: no numbering, no reversible mapping file. The
original file is **never modified** - a new file with a `.redacted`
suffix is written next to it (unless `--stdout` is used).

Timestamps (e.g. `14:32:10`) are correctly distinguished from IPv6
addresses and are left untouched.

## Install

### Snap (recommended, any Ubuntu / most Linux distros)

```bash
sudo snap install log-redact
```

The snap package is named `log-redact` (the name `redact` was already
taken in the Snap Store by an unrelated app). The installed command is
`log-redact.redact` by default; to use the shorter `redact` command,
create an alias once:

```bash
sudo snap alias log-redact.redact redact
```

### From source

```bash
git clone https://github.com/msmarcal/redact.git
cd redact
python3 -m pip install --user .
```

No install, run directly:

```bash
python3 -m redact file.log
```

## Usage

```bash
# Redact a single file -> writes file.log.redacted
redact file.log

# Multiple files at once
redact *.log config.yaml

# Additional client-specific domains not covered by the generic
# hostname pattern (custom TLDs, or to explicitly scope an engagement)
redact file.log --domain client.example --domain internal.client.net

# Print to stdout instead of writing a file (useful for piping/reviewing)
redact file.log --stdout

# Custom output suffix
redact file.log --suffix .clean
```

## Example

Input:

```
2026-08-24 10:00:01 server01.internal sshd: Accepted publickey for msmarcal from 192.168.100.14 port 52344
Config: password=Sup3rS3cr3t!2026
contact: marcelo@example.com
```

Output (`file.log.redacted`):

```
2026-08-24 10:00:01 [REDACTED-HOSTNAME] sshd: Accepted publickey for msmarcal from [REDACTED-IP] port 52344
Config: password=[REDACTED-CREDENTIAL]
contact: [REDACTED-EMAIL]
```

## Known limitations

- Hostname detection requires at least two dot-separated labels ending in
  a recognized TLD/suffix (`.com`, `.net`, `.internal`, `.local`, `.corp`,
  `.lan`, `.intranet`, `.io`, `.dev`, `.cloud`, `.xyz`, `.ai`, `.delivery`,
  `.co`, `.edu`, `.gov`, `.info`, `.biz`). A bare short hostname with no
  domain suffix (e.g. `webserver01`) is intentionally **not** redacted, to
  avoid false positives on ordinary words.
- Credential detection relies on known patterns and common `key=value`
  naming conventions. It is not a substitute for careful manual review
  before publishing sensitive files - always check the `.redacted` output
  before posting it anywhere.
- Business-sensitive data that isn't a technical identifier (project
  codenames, contract numbers, etc) is out of scope and won't be caught
  automatically.

## Prior art / Alternatives

Several other tools cover similar ground. None matched this project's
exact combination (offline stdlib-only CLI, fixed placeholders with no
reversible mapping file, per-engagement `--domain` scoping, packaged as a
snap), but they're worth knowing about:

| Project | Type | Notes |
|---|---|---|
| [hiranp/log-redactor](https://github.com/hiranp/log-redactor) | CLI (Python + Rust) | Closest in spirit. Also redacts URLs, phone numbers, names; supports PDFs and tar/zip archives; interactive confirm mode; rules kept in `secrets.json`/`ignores.json`. Keeps a reversible `redacted-mapping.txt` by default. |
| [Splunk support-scripts/log-redactor](https://github.com/splunk/support-scripts/blob/main/log-redactor/README.md) | CLI (Python) | Built for sanitizing Splunk diag bundles before sending to support. Uses **consistent per-value IDs** (`[REDACTED-IP-482910]`) with optional mapping export (`--json-export`/`--csv-export`) - the numbered+reversible model this project deliberately avoids. |
| [python-log-redactor](https://pypi.org/project/python-log-redactor) | Python library | Not a standalone file CLI - designed to hook into `logging` (a `RedactingFilter`) and redact dicts/strings inline in application code. |
| [LogShield](https://logshield.dev) / `logshield-cli` | CLI (Node) | Deterministic, offline, stdin/stdout pipeline (`cat app.log \| logshield scan`), `--fail-on-detect` for CI gating. Good overlap on vendor-token coverage (AWS, GitHub, Slack, npm, Stripe). Note: the PyPI package `logshield` is a *different*, hosted product that sends text to a RapidAPI backend - only the `logshield-cli` npm package is fully local. |
| [Log Redactor (jsondevtools.org)](https://jsondevtools.org/log-redactor.html) | Browser tool | Paste-in web page, client-side JS only, no upload. Not a CLI, doesn't fit a terminal/scripted workflow. |

If a future need comes up for PDF or archive redaction, `hiranp/log-redactor`
is the most likely tool to reach for instead of extending this one.

## Development

```bash
git clone https://github.com/msmarcal/redact.git
cd redact
python3 -m unittest discover -s tests -v
```

## Publishing to the Snap Store

Requires an Ubuntu machine (or LXD/multipass) with `snapcraft` installed,
and a registered Ubuntu One account.

```bash
sudo snap install snapcraft --classic

# Log in (only needed once per machine)
snapcraft login

# Register the name "log-redact" in the Snap Store (one-time; check first
# with `snapcraft search log-redact` in case it's since been taken)
snapcraft register log-redact

# Build the snap locally
snapcraft

# Manual upload + release to a channel
snapcraft upload --release=edge log-redact_1.0.0_amd64.snap
```

### Automating releases via GitHub Actions

The `.github/workflows/snap.yml` workflow builds the snap on every push and
PR (as a downloadable artifact) but does **not** publish by default. To
enable automatic publishing:

1. Generate store credentials locally:
   ```bash
   snapcraft export-login --snaps=log-redact --channels=edge,beta,candidate,stable -
   ```
2. Copy the output and save it as a repo secret named
   `SNAPCRAFT_STORE_CREDENTIALS` (Settings -> Secrets and variables ->
   Actions -> New repository secret).
3. Uncomment the "Release to edge channel" / "Release tagged version to
   stable channel" steps in `.github/workflows/snap.yml`.
4. Push to `main` (releases to `edge`) or push a `vX.Y.Z` tag (releases to
   `stable`).

## License

MIT - see [LICENSE](LICENSE).
