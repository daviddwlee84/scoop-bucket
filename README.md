# scoop-bucket

A [Scoop](https://scoop.sh) bucket for daviddwlee84's CLI tools.

```powershell
scoop bucket add daviddwlee84 https://github.com/daviddwlee84/scoop-bucket
scoop install daviddwlee84/translate
```

## Manifests

| App | Description | Source |
|---|---|---|
| `translate` | Fast terminal translation tool (CLI + TUI) | [daviddwlee84/translate](https://github.com/daviddwlee84/translate) |

## Maintenance

**Manifests in `bucket/` are generated — do not edit them by hand.** Each one is
written by GoReleaser in its source repository's release workflow and pushed
here on every tag; the next release overwrites local edits.

To change how a manifest is produced, edit the `scoops:` block in the source
repo's `.goreleaser.yaml`.
