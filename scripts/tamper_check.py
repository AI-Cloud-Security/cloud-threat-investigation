"""Create a modified copy and verify that the same trusted key rejects it."""
import argparse, json, subprocess, sys
from pathlib import Path
from cloud_threat.core.canonical import canonical
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--data', required=True)
a = p.parse_args()
folder = Path(a.data)
b = json.loads((folder / 'bundle.json').read_text())
b['payload']['issued_at'] = 'sampleNSTRATION-TAMPER'
target = folder / 'tampered.json'
with target.open('xb') as f:
    f.write(canonical(b))
r = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / 'run.py'), 'verify', str(target), '--trusted-key', str(folder / 'trusted_public_key.bin')])
if r.returncode != 1:
    raise SystemExit('FAIL: the modified bundle was not rejected as expected')
print('PASS: the modified copy failed verification. The original bundle is unchanged.')
