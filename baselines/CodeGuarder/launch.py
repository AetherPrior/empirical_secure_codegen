"""Run the end-to-end smoke check, then the full resumable campaign."""
import json
import subprocess
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
status=HERE/'outputs/launch_status.json'
for mode,flags in [('smoke',['--smoke']),('full',[])]:
    status.write_text(json.dumps(dict(status='running',phase=mode),indent=2))
    result=subprocess.run([sys.executable,'-u',str(HERE/'run.py'),*flags])
    if result.returncode:
        status.write_text(json.dumps(dict(status='failed',phase=mode,returncode=result.returncode),indent=2))
        raise SystemExit(result.returncode)
status.write_text(json.dumps(dict(status='complete'),indent=2))
