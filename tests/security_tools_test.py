import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]

def load(name, location):
    spec = importlib.util.spec_from_file_location(name, location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

scanner = load('scan', ROOT / 'scripts/scan_secrets.py')
backups = load('backup', ROOT / 'scripts/backup.py')

class SecurityToolsTests(unittest.TestCase):
    def test_secret_detector_and_output_redaction(self):
        fake = 'api_' + 'key = "' + 'x' * 40 + '"'
        self.assertTrue(scanner.findings(fake))
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'sample.txt').write_text(fake)
            r = subprocess.run(['python', str(ROOT / 'scripts/scan_secrets.py'), '--path', folder], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn('literal-secret', r.stdout)
            self.assertNotIn('x' * 40, r.stdout)

    def test_tracked_env_is_refused_and_deleted_secrets_remain_detectable(self):
        with tempfile.TemporaryDirectory() as folder:
            def git(*args):
                return subprocess.run(['git', *args], cwd=folder, check=True, capture_output=True)
            git('init', '-q')
            git('config', 'user.name', 'Security Test')
            git('config', 'user.email', 'security-test@example.invalid')
            Path(folder, '.env').write_text('PORT=3000\n')
            git('add', '.env')
            git('commit', '-qm', 'test config')
            r = subprocess.run(['python', str(ROOT / 'scripts/scan_secrets.py'), '--path', folder], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn('sensitive-file-tracked', r.stdout)
            Path(folder, 'old.txt').write_text('api_' + 'key = "' + 'x' * 40 + '"')
            git('add', 'old.txt'); git('commit', '-qm', 'test secret detector')
            git('rm', '.env', 'old.txt'); git('commit', '-qm', 'delete test fixture')
            r = subprocess.run(['python', str(ROOT / 'scripts/scan_secrets.py'), '--path', folder, '--history'], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn('git-history-diff', r.stdout)
            self.assertNotIn('x' * 40, r.stdout)

    def test_backup_refuses_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder, 'evil.zip')
            with ZipFile(archive, 'w') as z:
                z.writestr('../outside', b'x')
                z.writestr('BACKUP-MANIFEST.json', json.dumps({'../outside': 'fake-checksum'}))
            with self.assertRaisesRegex(ValueError, 'Unsafe backup path'):
                backups.restore_test(archive)
            self.assertFalse(Path(folder, 'outside').exists())

    def test_backup_never_selects_actual_env_or_dependency_files(self):
        files = {p.relative_to(ROOT).as_posix() for p in backups.source_files()}
        self.assertIn('.env.example', files)
        self.assertTrue({'compose.yaml','Dockerfile','.dockerignore','MICROSERVICES.md','services/identity/server.cjs','services/legal/data.js','packages/storage/index.cjs','migrations/001_identity.sql'} <= files)
        self.assertNotIn('.env', files)
        self.assertFalse(any('.runtime/' in p or 'private/' in p or p.endswith('.haqpg') for p in files))
        self.assertFalse(any('node_modules' in p for p in files))
        self.assertFalse(any('backups/' in p for p in files))

    def test_monitoring_alert_and_clean_window(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder, 'events.jsonl')
            log.write_text(json.dumps({'time': datetime.now(timezone.utc).isoformat(), 'event': 'server_error'}) + '\n')
            r = subprocess.run(['python', str(ROOT / 'scripts/monitor_logs.py'), str(log)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertTrue(json.loads(r.stdout)['alert'])
            log.write_text(json.dumps({'time': datetime.now(timezone.utc).isoformat(), 'event': 'server_started'}) + '\n')
            r = subprocess.run(['python', str(ROOT / 'scripts/monitor_logs.py'), str(log)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertFalse(json.loads(r.stdout)['alert'])

if __name__ == '__main__':
    unittest.main()
