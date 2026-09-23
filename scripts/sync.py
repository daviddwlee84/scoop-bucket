#!/usr/bin/env python3
"""Verify immutable Windows releases before publishing the four personal Scoop manifests."""
from __future__ import annotations
import argparse, hashlib, json, os, re, struct, subprocess, sys, tempfile, time
import urllib.error, urllib.request, zipfile
from pathlib import Path, PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
TARGETS=("windows_amd64","windows_arm64")
TAG=re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256=re.compile(r"^[0-9a-f]{64}$")
SCOOP_SHA="b588a06e41d920d2123ec70aee682bae14935939"
def fetch(url):
    headers = {"User-Agent": "personal-scoop-release-sync"}
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))


def checksum_map(text):
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2 or not SHA256.fullmatch(fields[0]):
            raise ValueError("invalid checksum line")
        name = fields[1].removeprefix("*")
        if name in result:
            raise ValueError("duplicate checksum: " + name)
        result[name] = fields[0]
    return result


def release_plan(tool, release, checksums):
    tag = release.get("tag_name", "")
    if not TAG.fullmatch(tag) or release.get("draft") or release.get("prerelease"):
        raise ValueError("latest release is not a stable vMAJOR.MINOR.PATCH release")
    assets = {}
    for asset in release.get("assets", []):
        if asset["name"] in assets:
            raise ValueError("duplicate release asset: " + asset["name"])
        assets[asset["name"]] = asset
    selected = {}
    sums = checksum_map(checksums)
    for target in TARGETS:
        system, arch = target.split("_")
        name = tool["archive"].format(tag=tag, version=tag[1:], os=system, arch=arch)
        if name not in assets or name not in sums:
            raise ValueError("missing release asset or checksum: " + name)
        asset = assets[name]
        expected_url = f'https://github.com/{tool["repo"]}/releases/download/{tag}/{name}'
        if asset.get("browser_download_url") != expected_url:
            raise ValueError("unexpected asset URL: " + name)
        digest = asset.get("digest")
        if digest and digest != "sha256:" + sums[name]:
            raise ValueError("API digest and checksum disagree: " + name)
        selected[target] = {"name": name, "url": expected_url, "sha256": sums[name],
                            "asset_id": asset["id"], "size": asset["size"]}
    manifest = assets.get(tool["checksums"])
    if not manifest:
        raise ValueError("missing checksum manifest")
    return {"version": tag[1:], "tag": tag, "release_id": release["id"],
            "checksum_asset_id": manifest["id"],
            "checksum_sha256": hashlib.sha256(checksums.encode("utf-8")).hexdigest(),
            "assets": selected}


def guard_previous(previous, plan):
    if not previous:
        return False
    old_version = tuple(map(int, previous["version"].split(".")))
    new_version = tuple(map(int, plan["version"].split(".")))
    if new_version < old_version:
        raise ValueError("refusing release downgrade")
    if new_version == old_version:
        if previous != plan:
            raise ValueError("same-tag release assets changed; publish a new immutable version")
        return True
    return False


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".sync-", delete=False) as output:
        staged = Path(output.name)
        output.write(content)
    try:
        staged.chmod(0o644)
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)


def render_manifest(tool, plan):
    architectures = {}
    updates = {}
    for arch, scoop_arch in (("amd64", "64bit"), ("arm64", "arm64")):
        asset = plan["assets"]["windows_" + arch]
        architectures[scoop_arch] = {"url": asset["url"], "hash": asset["sha256"], "bin": tool["binary"] + ".exe"}
        updates[scoop_arch] = {"url": "https://github.com/" + tool["repo"] + "/releases/download/v$version/" + tool["archive"].format(version="$version", tag="v$version", os="windows", arch=arch)}
    return (json.dumps({"version": plan["version"], "description": tool["description"],
        "homepage": "https://github.com/" + tool["repo"], "license": tool["license"],
        "architecture": architectures, "checkver": {"github": "https://github.com/" + tool["repo"]},
        "autoupdate": {"architecture": updates, "hash": {"url": "https://github.com/" + tool["repo"] + "/releases/download/v$version/" + tool["checksums"]}}}, indent=2) + "\n").encode()


def verify_zip(content, binary, arch):
    import io
    required = {binary + ".exe", "LICENSE", "completions/" + binary + ".bash", "completions/" + binary + ".zsh", "completions/" + binary + ".ps1"}
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        files = [m for m in members if not m.is_dir()]
        if len(files) != len(required) or {m.filename for m in files} != required:
            raise ValueError("unexpected, duplicate, or missing ZIP member")
        if any(m.filename != "completions/" for m in members if m.is_dir()):
            raise ValueError("unexpected ZIP directory")
        if any(((m.external_attr >> 16) & 0o170000) not in (0, 0o100000) or m.file_size > 256*1024*1024 for m in files):
            raise ValueError("unsafe ZIP entry")
        data = {m.filename: archive.read(m) for m in files}
    if any(not value.strip() for value in data.values()):
        raise ValueError("empty release payload")
    payload = data[binary + ".exe"]
    valid = False
    if len(payload) >= 64 and payload[:2] == b"MZ":
        offset = struct.unpack_from("<I", payload, 60)[0]
        if offset >= 64 and offset + 26 <= len(payload):
            valid = payload[offset:offset+4] == b"PE\0\0" and struct.unpack_from("<H", payload, offset+4)[0] == {"amd64": 0x8664, "arm64": 0xaa64}[arch] and struct.unpack_from("<H", payload, offset+24)[0] == 0x20b
    if not valid:
        raise ValueError("Windows PE architecture disagrees with asset name")
    return data


def run(argv, env=None):
    result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=300)
    if result.returncode:
        raise RuntimeError("command failed: " + str(argv) + "\n" + result.stdout + result.stderr)
    return result.stdout


def scoop_environment(work):
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("real Scoop acceptance requires a disposable hosted Windows runner")
    import datetime
    scoop = work / "scoop"
    manager = scoop / "apps/scoop/current"
    run(["git", "init", str(manager)])
    run(["git", "-C", str(manager), "remote", "add", "origin", "https://github.com/ScoopInstaller/Scoop"])
    run(["git", "-C", str(manager), "fetch", "--depth", "1", "origin", SCOOP_SHA])
    run(["git", "-C", str(manager), "checkout", "--detach", "FETCH_HEAD"])
    home = work / "home"
    config = home / "config/scoop/config.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"last_update": datetime.datetime.now().isoformat(), "aria2-enabled": False, "show_update_log": False}))
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), SCOOP=str(scoop), SCOOP_GLOBAL=str(work / "global-unused"),
        XDG_CONFIG_HOME=str(home / "config"), XDG_CACHE_HOME=str(home / "cache"), XDG_DATA_HOME=str(home / "data"), XDG_STATE_HOME=str(home / "state"))
    env["PATH"] = str(scoop / "shims") + os.pathsep + env["PATH"]
    bucket = scoop / "buckets/daviddwlee84"
    bucket.parent.mkdir(parents=True)
    # The isolated bucket sees the exact uncommitted candidate being verified.
    junction_script = work / "register-bucket.ps1"
    junction_script.write_text("param([string]$Link, [string]$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n")
    run(["pwsh", "-NoProfile", "-File", str(junction_script), str(bucket), str(ROOT)], env)
    return env, ["pwsh", "-NoLogo", "-NoProfile", "-File", str(manager / "bin/scoop.ps1")]


def verify_native(tool, plan, env, scoop):
    name, binary = tool["id"], tool["binary"]
    run(scoop + ["install", "daviddwlee84/" + name], env)
    executable = str(Path(env["SCOOP"]) / "apps" / name / "current" / (binary + ".exe"))
    version = run([executable, "--version"], env).strip()
    if version != binary + " version " + plan["tag"]:
        raise ValueError("installed version does not match the selected immutable tag")
    run([executable, "--help"], env)
    completion = run([executable, "completion", "powershell"], env)
    if "Register-ArgumentCompleter" not in completion:
        raise ValueError("installed executable has no PowerShell completion")
    check = json.loads(run([executable, "upgrade", "--check", "--json"], env))
    check = check.get("data", check)
    if check.get("manager") != "scoop" or check.get("package") != name or check.get("bucket") != "daviddwlee84" or not check.get("can_upgrade"):
        raise ValueError("installed binary did not verify its actual Scoop owner")
    print(name + ": native version/help/completion/upgrade-check passed", flush=True)


def synchronize(tool, write=False, native=None):
    release = json.loads(fetch("https://api.github.com/repos/" + tool["repo"] + "/releases/latest"))
    tag = release.get("tag_name", "")
    if not TAG.fullmatch(tag):
        raise ValueError("release tag is not stable")
    sums_url = "https://github.com/" + tool["repo"] + "/releases/download/" + tag + "/" + tool["checksums"]
    if not any(a["name"] == tool["checksums"] and a.get("browser_download_url") == sums_url for a in release.get("assets", [])):
        raise ValueError("missing official checksum asset")
    sums = fetch(sums_url)
    sums_asset = next(a for a in release["assets"] if a["name"] == tool["checksums"])
    if sums_asset.get("digest") and sums_asset["digest"] != "sha256:" + hashlib.sha256(sums).hexdigest():
        raise ValueError("checksum asset digest disagrees with GitHub")
    plan = release_plan(tool, release, sums.decode("utf-8"))
    manifest_path = ROOT / "bucket" / (tool["id"] + ".json")
    receipt_path = ROOT / ".sync-state" / (tool["id"] + ".json")
    previous = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
    rendered = render_manifest(tool, plan)
    if guard_previous(previous, plan):
        if not manifest_path.exists() or manifest_path.read_bytes() != rendered:
            raise ValueError("unchanged release has manifest drift; inspect before overwriting")
        print(tool["id"] + ": unchanged " + plan["tag"], flush=True)
        return False
    for target, asset in plan["assets"].items():
        content = fetch(asset["url"])
        if len(content) != asset["size"] or hashlib.sha256(content).hexdigest() != asset["sha256"]:
            raise ValueError("release archive size/checksum mismatch")
        verify_zip(content, tool["binary"], target.split("_")[1])
    if not write:
        print(tool["id"] + ": verified candidate " + plan["tag"], flush=True)
        return False
    old = manifest_path.read_bytes() if manifest_path.exists() else None
    old_receipt = receipt_path.read_bytes() if receipt_path.exists() else None
    try:
        atomic_write(manifest_path, rendered)
        if native:
            verify_native(tool, plan, *native)
        else:
            raise ValueError("writing manifests requires native Scoop validation")
        receipt_path.parent.mkdir(exist_ok=True)
        atomic_write(receipt_path, (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode())
    except Exception:
        for path, content in ((manifest_path, old), (receipt_path, old_receipt)):
            if content is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, content)
        raise
    print(tool["id"] + ": updated " + plan["tag"], flush=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", help="comma-separated registry tool IDs; default all four")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--scoop-smoke", action="store_true")
    args = parser.parse_args()
    tools = json.loads((ROOT / "tools.json").read_text())
    selected = set(args.tool.split(",")) if args.tool else {t["id"] for t in tools}
    if selected - {t["id"] for t in tools}:
        parser.error("unknown tool; dev-cli and translate retain their existing publishers")
    if args.write and not args.scoop_smoke:
        parser.error("--write requires --scoop-smoke")
    failures = []
    with tempfile.TemporaryDirectory(prefix="verified-scoop-") as work:
        native = scoop_environment(Path(work)) if args.scoop_smoke else None
        for tool in tools:
            if tool["id"] not in selected:
                continue
            try:
                synchronize(tool, args.write, native)
            except Exception as error:
                failures.append(tool["id"])
                print(tool["id"] + ": FAILED: " + str(error), file=sys.stderr, flush=True)
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
