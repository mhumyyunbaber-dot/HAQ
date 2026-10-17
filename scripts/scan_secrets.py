"""Dependency-free secret-pattern and tracked-sensitive-file gate.
Not a substitute for platform secret scanning or a full credential audit.
Only filenames, line numbers and rule names are printed; never matched values.
"""
from pathlib import Path
import argparse
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'node_modules', '.git', '__pycache__', '.cache', 'coverage', 'playwright-report', 'test-results', 'backups', 'private', '.tools', '.runtime'}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b'),
    'aws-access-key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'model-api-key': re.compile(r'\bsk-(?:proj-|ant-api\d{2}-)?[A-Za-z0-9_-]{30,}\b'),
    'credential-url': re.compile(r'\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/]+:[^\s@]+@', re.I),
    'literal-secret': re.compile(r'''(?:api[_-]?key|client[_-]?secret|jwt[_-]?secret|secret[_-]?key|password|security[_-]?log[_-]?key)\s*["']?\s*[:=]\s*["']([A-Za-z0-9_+/=.\-]{20,})["']''', re.I),
}

def findings(content):
    found = []
    for number, line in enumerate(content.splitlines(), 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                found.append((number, name))
    return found

def sensitive_filename(name):
    p = Path(name)
    return ((p.name == '.env' or p.name.startswith('.env.')) and p.name != '.env.example') or p.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'} or p.name in {'credentials.json', '.netrc', '.npmrc'} or p.name.startswith('service-account')

def run(root, history=False):
    failures = []
    count = 0
    for file in sorted(root.rglob('*')):
        relative = file.relative_to(root)
        if (sensitive_filename(str(relative)) and relative.name.startswith('.env')) or any(p in SKIP for p in relative.parts) or not file.is_file() or file.is_symlink():
            continue
        if file.stat().st_size > 2_000_000:
            failures.append((str(relative), 0, 'file-too-large-to-scan'))
            continue
        data = file.read_bytes()
        if b'\0' in data:
            continue
        count += 1
        for line, rule in findings(data.decode('utf-8', errors='replace')):
            failures.append((str(relative), line, rule))
    git = subprocess.run(['git', 'rev-parse', '--show-toplevel'], cwd=root, capture_output=True, text=True)
    if git.returncode == 0 and Path(git.stdout.strip()).resolve() == root.resolve():
        tracked = subprocess.run(['git', 'ls-files', '-z'], cwd=root, check=True, capture_output=True).stdout.decode().split('\0')
        for name in tracked:
            if name and sensitive_filename(name):
                failures.append((name, 0, 'sensitive-file-tracked'))
        if history:
            log = subprocess.run(['git', 'log', '-p', '--all', '--no-ext-diff', '--no-color', '--format=commit:%h'], cwd=root, capture_output=True)
            if log.returncode:
                failures.append(('git-history', 0, 'history-scan-failed'))
            elif len(log.stdout) > 20_000_000:
                failures.append(('git-history', 0, 'history-too-large-use-dedicated-scanner'))
            else:
                for line, rule in findings(log.stdout.decode('utf-8', errors='replace')):
                    failures.append(('git-history-diff', line, rule))
            print('Local Git diff history checked across all local refs (not unreachable objects/LFS/remote-only refs).')
    else:
        print('No local Git repository: tracked-file/history scan SKIPPED. Remote repository not inspected.')
    for file, line, rule in failures:
        print(f'FAIL {file}:{line} [{rule}]')
    print(f'Scanned {count} local text files; {len(failures)} findings. Pattern coverage is limited.')
    return 1 if failures else 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--history', action='store_true')
    parser.add_argument('--path', type=Path, default=ROOT)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        fake = 'api_' + 'key = "' + ('x' * 40) + '"'
        assert findings(fake)
        assert not findings('PORT=3000\nSECURITY_LOG_KEY=\n')
        assert sensitive_filename('.env.production') and not sensitive_filename('.env.example')
        print('Secret scanner self-tests passed.')
    else:
        sys.exit(run(args.path.resolve(), args.history))
