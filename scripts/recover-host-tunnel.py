#!/usr/bin/env python3
"""One-shot recovery of this host's journal-proven Agent Tunnel rules."""
import json
import os
import subprocess

ROOT = '/home/den/.config/AntigravitiProxi'
IP = '/usr/sbin/ip'

def run(*args):
    return subprocess.check_output([IP, *args], text=True)

if os.geteuid() != 0:
    raise SystemExit('Administrator privileges required')
with open(ROOT + '/network-state.json') as f:
    journal = json.load(f)
if journal.get('operation_id') != '1788596937804836637-17252':
    raise SystemExit('Journal changed; refusing recovery')
if journal.get('pid', 0) and os.path.exists('/proc/' + str(journal['pid'])):
    raise SystemExit('Journal process still alive')
if any(link['ifname'] == 'antigravity-tun'
       for link in json.loads(run('-j', 'link', 'show'))):
    raise SystemExit('TUN exists; re-audit required')
for entry in os.scandir('/proc'):
    if entry.name.isdigit():
        try:
            with open(entry.path + '/comm') as f:
                if f.read().strip() == 'sing-box':
                    raise SystemExit('sing-box is running; refusing recovery')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
for family, key in [('-4', 'v4'), ('-6', 'v6')]:
    before = journal['before']['rules_' + key]
    if any(19000 <= int(line.split(':')[0]) <= 19031 for line in before):
        raise SystemExit('Reserved priorities were not empty before transaction')
    owned = set(journal['owned']['new_rule_priorities_' + key])
    for rule in json.loads(run('-j', family, 'rule', 'show')):
        priority = rule.get('priority', -1)
        if 19000 <= priority <= 19031 and priority in owned:
            subprocess.run([IP, family, 'rule', 'del', 'priority', str(priority)], check=True)
            print(f'Removed {family} rule {priority}', flush=True)
    # TUN is absent; do not flush any table containing unrelated interfaces.
    routes = [r for r in json.loads(run('-j', family, 'route', 'show', 'table', 'all'))
              if str(r.get('table')) == '20229']
    if routes:
        raise SystemExit('Table 20229 still contains routes; re-audit required')
print('Owned stale rules removed; other routing tables untouched')
