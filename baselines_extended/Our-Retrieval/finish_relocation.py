"""Adopt active generations, retire the temporary old path, and resume workers."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
out=HERE/'outputs'
info=json.loads((out/'relocation.json').read_text())


def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split()[0]!='Z'
    except FileNotFoundError:
        return False


while True:
    active=[p for p in info['active_generations'] if alive(p)]
    (out/'relocation_status.json').write_text(json.dumps(dict(status='waiting_for_active_generations',pids=active),indent=2))
    if not active:break
    time.sleep(15)
for pid in info['schedulers']:
    if alive(pid):
        command=Path(f'/proc/{pid}/cmdline').read_text()
        if 'Our-Retrieval/run.py' not in command:
            raise RuntimeError(f'PID {pid} no longer belongs to the old scheduler')
        os.kill(pid,signal.SIGTERM)
        os.kill(pid,signal.SIGCONT)
# Wait for the old language locks to be released.
while any(alive(p) for p in info['schedulers']):time.sleep(1)
old=Path(info['old'])
if not old.is_symlink() or old.resolve()!=HERE:
    raise RuntimeError('Unexpected old-path entry; refusing to remove it')
old.unlink()
for p in out.rglob('*.json'):
    if 'frozen' in p.relative_to(out).parts or p.name in ['prepared_cases.json','base_cases.json','relocation.json']:
        continue
    text=p.read_text()
    changed=text.replace(info['old'],str(HERE))
    if changed!=text:p.write_text(changed)
with (out/'logs/launch.log').open('a') as log:
    proc=subprocess.Popen([sys.executable,'-u',str(HERE/'run.py')],stdout=log,stderr=subprocess.STDOUT,
                          start_new_session=True,cwd=HERE.parents[1])
(out/'launch.pid').write_text(str(proc.pid)+'\n')
(out/'relocation_status.json').write_text(json.dumps(dict(status='complete',supervisor_pid=proc.pid),indent=2))
