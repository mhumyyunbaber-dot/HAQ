"""Build a portable HTML file with a hash-restricted, offline Content Security Policy."""
from pathlib import Path
import base64
import hashlib
import re

root = Path(__file__).resolve().parent
# Legal-reference service owns the canonical public catalog; mirror for offline builds.
(root / 'data.js').write_bytes((root / 'services/legal/data.js').read_bytes())
html = (root / 'index.html').read_text()
css = '\n' + (root / 'style.css').read_text() + '\n'
html = html.replace('<link rel="stylesheet" href="style.css">', '<style>' + css + '</style>')
scripts = []
for name in ('data.js', 'app.js', 'auth-ui.js'):
    code = '\n' + (root / name).read_text().replace('</script', '<\\/script') + '\n'
    scripts.append(code)
    html = html.replace(f'<script src="{name}"></script>', '<script>' + code + '</script>')

def digest(content):
    return "'sha256-" + base64.b64encode(hashlib.sha256(content.encode()).digest()).decode() + "'"

policy = "; ".join([
    "default-src 'none'",
    'script-src ' + ' '.join(digest(s) for s in scripts),
    "script-src-attr 'none'",
    'style-src ' + digest(css),
    "style-src-attr 'none'",
    "img-src data:", "connect-src 'none'", "object-src 'none'",
    "base-uri 'none'", "form-action 'none'", "frame-src 'none'", "worker-src 'none'",
])
html = html.replace('<meta charset="UTF-8">', '<meta charset="UTF-8"><meta http-equiv="Content-Security-Policy" content="' + policy + '"><meta name="referrer" content="no-referrer">', 1)
if re.search(r'\sstyle\s*=|\son\w+\s*=', html, re.I):
    raise SystemExit('Inline style/event attributes must not be used')
(root / 'Haq.html').write_text(html)
print('Built standalone HTML with pinned script/style hashes.')
