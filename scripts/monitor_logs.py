"""Read a bounded JSONL export of Haq's structured security logs.
Exits nonzero when a configured threshold is exceeded, for a scheduled alert job.
Does not send an external notification by itself.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('file', type=Path)
p.add_argument('--minutes', type=int, default=5)
p.add_argument('--threshold', type=int, default=20)
a = p.parse_args()
if not 1 <= a.minutes <= 1440 or not 1 <= a.threshold <= 100000:
    p.error('Invalid monitoring bounds')
if a.file.stat().st_size > 20_000_000:
    p.error('Rotate logs before monitoring (maximum 20 MB)')
cutoff = datetime.now(timezone.utc) - timedelta(minutes=a.minutes)
counts = Counter()
for line in a.file.open():
    try:
        record = json.loads(line)
        when = datetime.fromisoformat(record['time'].replace('Z', '+00:00'))
        event = record.get('event')
        if event in {'rate_limit', 'origin_rejected', 'invalid_host', 'invalid_target', 'method_rejected', 'request_body_rejected', 'server_error', 'not_found', 'https_required', 'cross_site_resource', 'auth_rate_limit', 'account_auth_rate_limit', 'bootstrap_rate_limit', 'verification_rate_limit', 'auth_error', 'oauth_failed', 'login_failed', 'mail_delivery_failed', 'upstream_unavailable'} and when >= cutoff:
            counts[event] += 1
    except (ValueError, KeyError, TypeError):
        continue
alert = (counts.get('server_error', 0) > 0 or counts.get('upstream_unavailable', 0) > 0 or counts.get('auth_error', 0) > 0) or sum(counts.values()) >= a.threshold
print(json.dumps({'alert': alert, 'window_minutes': a.minutes, 'counts': dict(counts)}))
raise SystemExit(1 if alert else 0)
