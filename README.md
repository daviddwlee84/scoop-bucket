# scoop-bucket

Verified Windows packages for personal CLI tools:

```powershell
scoop bucket add daviddwlee84 https://github.com/daviddwlee84/scoop-bucket
scoop install daviddwlee84/translate
scoop install daviddwlee84/exp-cli
scoop install daviddwlee84/lazyclash
scoop install daviddwlee84/lazypueue
scoop install daviddwlee84/lazychezmoi
scoop install daviddwlee84/lazymlflow
```

`exp-cli` provides `exp.exe`. The existing `dev-cli` package provides `dev.exe`;
Windows dotfiles deliberately retain their separate verified `dev-cli.exe`
installation to avoid Microsoft's unrelated `dev` command.

## Manifest ownership

Manifests are generated. `dev-cli` and `translate` retain their existing source
repository publishers. This repository's `tools.json` and `scripts/sync.py` own
only exp-cli and the four lazy manifests; source repositories publish immutable
releases and do not need a token to write this bucket.

The central workflow runs hourly and accepts a comma-separated selection:

```sh
gh workflow run sync.yml --repo daviddwlee84/scoop-bucket \
  -f tool=exp-cli,lazyclash,lazypueue,lazychezmoi,lazymlflow
```

It verifies both amd64/arm64 ZIP assets, their exact SHA256 manifest, safe ZIP
members and PE architecture before writing a candidate manifest. A disposable
Windows runner then installs through real Scoop and checks version, help,
PowerShell completion and the executable's read-only upgrade ownership probe.
ARM64 payloads are inspected; execution acceptance is on native amd64.

Only validated changes are committed. A failed package retains its prior
manifest and receipt; independent successes can be committed while the job
still fails. Same-tag asset changes and version downgrades are rejected.
Repeating a successful sync produces `unchanged` results without another
install or commit. Receipts live in `.sync-state/`.

## Upgrade behavior

Use `scoop update <package>` for external updates. The five centrally managed
CLIs also expose `upgrade --check` and tracked Scoop handoff: the original
process exits before an independent helper updates the package. Initial
`handed-off` output is acceptance, not success. Use the returned `status_command`
while the update runs, then inspect its verified result. Directly polling the
installed executable can itself make Scoop defer an update as a running app.
A host that denies job breakaway requires its launching terminal to remain open.

No package installs backend services, Go toolchains or agent skills implicitly.

## Maintainer checks

```sh
python -m unittest discover -s tests
python scripts/sync.py --tool exp-cli   # read-only release verification
```

Writing manifests requires `--write --scoop-smoke` on a disposable GitHub-hosted
Windows runner. Never edit a generated manifest or replace a published release
asset to repair an unsuccessful verification.
