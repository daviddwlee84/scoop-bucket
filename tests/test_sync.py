import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import sync


class SyncTests(unittest.TestCase):
    def archive(self, arch='amd64', extra=None):
        data = bytearray(128)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, {'amd64': 0x8664, 'arm64': 0xaa64}[arch])
        struct.pack_into('<H', data, 88, 0x20b)
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            for name, value in {'exp.exe': bytes(data), 'LICENSE': b'MIT', 'completions/exp.bash': b'bash', 'completions/exp.zsh': b'zsh', 'completions/exp.ps1': b'powershell'}.items():
                archive.writestr(name, value)
            if extra:
                archive.writestr(extra, b'unexpected')
        return out.getvalue()

    def fixture(self):
        tool = json.loads((sync.ROOT / 'tools.json').read_text())[0]
        assets, payloads, lines = [], {}, []
        for i, arch in enumerate(['amd64', 'arm64']):
            name = f'exp-cli_0.2.0_windows_{arch}.zip'
            content = self.archive(arch)
            digest = hashlib.sha256(content).hexdigest()
            url = f'https://github.com/{tool["repo"]}/releases/download/v0.2.0/{name}'
            assets.append({'id': i+1, 'name': name, 'size': len(content), 'digest': 'sha256:'+digest, 'browser_download_url': url})
            payloads[url] = content
            lines.append(digest+'  '+name)
        sums = ('\n'.join(lines)+'\n').encode()
        url = f'https://github.com/{tool["repo"]}/releases/download/v0.2.0/checksums.txt'
        payloads[url] = sums
        assets.append({'id': 3, 'name': 'checksums.txt', 'size': len(sums), 'digest': 'sha256:'+hashlib.sha256(sums).hexdigest(), 'browser_download_url': url})
        release = {'id': 99, 'tag_name': 'v0.2.0', 'draft': False, 'prerelease': False, 'assets': assets}
        payloads[f'https://api.github.com/repos/{tool["repo"]}/releases/latest'] = json.dumps(release).encode()
        return tool, release, sums, payloads

    def test_only_five_new_publishers_are_owned(self):
        tools = json.loads((sync.ROOT / 'tools.json').read_text())
        self.assertEqual({t['id'] for t in tools}, {'exp-cli', 'lazyclash', 'lazypueue', 'lazychezmoi', 'lazymlflow'})

    def test_both_architectures_and_binary_alias(self):
        tool, release, sums, _ = self.fixture()
        plan = sync.release_plan(tool, release, sums.decode())
        manifest = json.loads(sync.render_manifest(tool, plan))
        self.assertEqual(set(manifest['architecture']), {'64bit', 'arm64'})
        self.assertEqual(manifest['architecture']['64bit']['bin'], 'exp.exe')
        self.assertEqual(manifest['version'], '0.2.0')
        for arch in ['amd64', 'arm64']:
            sync.verify_zip(self.archive(arch), 'exp', arch)

    def test_incomplete_assets_and_same_tag_drift_fail(self):
        tool, release, sums, _ = self.fixture()
        plan = sync.release_plan(tool, release, sums.decode())
        self.assertTrue(sync.guard_previous(plan, plan))
        changed = json.loads(json.dumps(plan))
        changed['assets']['windows_amd64']['asset_id'] = 300
        with self.assertRaisesRegex(ValueError, 'same-tag'):
            sync.guard_previous(plan, changed)
        release['assets'].pop(0)
        with self.assertRaisesRegex(ValueError, 'missing release'):
            sync.release_plan(tool, release, sums.decode())

    def test_zip_safety_and_machine_architecture(self):
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            sync.verify_zip(self.archive(extra='../outside'), 'exp', 'amd64')
        with self.assertRaisesRegex(ValueError, 'architecture'):
            sync.verify_zip(self.archive('arm64'), 'exp', 'amd64')

    def test_failed_native_install_restores_previous_bytes(self):
        tool, _, _, payloads = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'bucket').mkdir()
            manifest = root / 'bucket/exp-cli.json'
            manifest.write_bytes(b'previous manifest')
            with mock.patch.object(sync, 'ROOT', root), mock.patch.object(sync, 'fetch', side_effect=lambda url: payloads[url]), mock.patch.object(sync, 'verify_native', side_effect=RuntimeError('fixture native failure')):
                with self.assertRaisesRegex(RuntimeError, 'native failure'):
                    sync.synchronize(tool, True, ({}, []))
            self.assertEqual(manifest.read_bytes(), b'previous manifest')
            self.assertFalse((root / '.sync-state/exp-cli.json').exists())

    def test_noop_does_not_download_archives_or_reinstall(self):
        tool, release, sums, payloads = self.fixture()
        plan = sync.release_plan(tool, release, sums.decode())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'bucket').mkdir()
            (root / '.sync-state').mkdir()
            (root / 'bucket/exp-cli.json').write_bytes(sync.render_manifest(tool, plan))
            (root / '.sync-state/exp-cli.json').write_text(json.dumps(plan))
            calls = []
            def fetch(url):
                calls.append(url)
                if url.endswith('.zip'):
                    raise AssertionError('no-op downloaded an archive')
                return payloads[url]
            with mock.patch.object(sync, 'ROOT', root), mock.patch.object(sync, 'fetch', side_effect=fetch), mock.patch.object(sync, 'verify_native') as native:
                self.assertFalse(sync.synchronize(tool, True, ({}, [])))
                native.assert_not_called()
            self.assertEqual(len(calls), 2)


if __name__ == '__main__':
    unittest.main()
