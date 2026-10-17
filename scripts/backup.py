"""Create and verify a source/config-template backup; never include secrets or case data.
Account databases use the separate encrypted postgres-backup.cjs tool; SQLite is legacy only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
TOP_FILES = ['compose.yaml', 'Dockerfile', '.dockerignore', 'MICROSERVICES.md', 'index.html', 'app.js', 'auth.cjs', 'auth-ui.js', 'AUTH-SETUP.md', 'data.js', 'style.css', 'server.cjs', 'package.json', 'package-lock.json', 'build.py', 'test.cjs', 'README.md', 'SECURITY.md', 'SECURITY-AUDIT.md', '.env.example', '.gitignore']
PREFIXES = ['scripts', 'tests', 'deploy', '.github', 'docs', 'services', 'packages', 'migrations']

def source_files():
    files = [ROOT / name for name in TOP_FILES if (ROOT / name).is_file()]
    for prefix in PREFIXES:
        files += [p for p in (ROOT / prefix).rglob('*') if p.is_file() and '__pycache__' not in p.parts and not p.is_symlink()]
    for p in files:
        if p.is_symlink() or p.name == '.env' or (p.name.startswith('.env.') and p.name != '.env.example'):
            raise ValueError('Sensitive or symlink file refused')
    return sorted(files)

def backup(destination):
    # Fail the backup if the local source scanner detects exposed credentials.
    import subprocess
    subprocess.run(['python', str(ROOT / 'scripts/scan_secrets.py')], check=True)
    manifest = {}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, 'w', ZIP_DEFLATED) as z:
        for file in source_files():
            name = file.relative_to(ROOT).as_posix()
            raw = file.read_bytes()
            manifest[name] = hashlib.sha256(raw).hexdigest()
            z.writestr(name, raw)
        z.writestr('BACKUP-MANIFEST.json', json.dumps(manifest, indent=2))
    destination.chmod(0o600)
    return manifest

def restore_test(archive):
    with ZipFile(archive) as z, tempfile.TemporaryDirectory(prefix='haq-restore-') as temp:
        if sum(i.file_size for i in z.infolist()) > 10_000_000:
            raise ValueError('Backup too large')
        manifest = json.loads(z.read('BACKUP-MANIFEST.json'))
        names = z.namelist()
        if len(names) != len(set(names)) or set(names) != set(manifest) | {'BACKUP-MANIFEST.json'}:
            raise ValueError('Invalid backup manifest')
        if sum(i.file_size for i in z.infolist()) > 10_000_000:
            raise ValueError('Backup too large')
        for name, checksum in manifest.items():
            path = Path(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Unsafe backup path')
            raw = z.read(name)
            if hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError('Checksum mismatch')
            target = Path(temp) / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        required = {'server.cjs', 'package-lock.json', 'index.html', 'app.js', 'auth.cjs', 'auth-ui.js', 'AUTH-SETUP.md', '.env.example', 'compose.yaml', 'Dockerfile', 'services/gateway/server.cjs', 'services/identity/server.cjs', 'services/web/server.cjs', 'services/legal/server.cjs', 'packages/storage/index.cjs', 'migrations/001_identity.sql'}
        if not required <= set(manifest):
            raise ValueError('Incomplete backup')
        for file in source_files():
            relative = file.relative_to(ROOT)
            if (Path(temp) / relative).read_bytes() != file.read_bytes():
                raise ValueError('Restored source differs')
        print(f'PASS: restored {len(manifest)} source/template files to an isolated temporary directory; all SHA-256 checksums match.')
        print('This is a source restore drill; account database snapshots use the separate encrypted backup tool.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'backups' / 'haq-source-backup.zip')
    parser.add_argument('--restore-test', action='store_true')
    args = parser.parse_args()
    backup(args.output.resolve())
    print('Source backup created (secrets excluded). Store an off-host copy with encryption and access controls.')
    if args.restore_test:
        restore_test(args.output.resolve())
