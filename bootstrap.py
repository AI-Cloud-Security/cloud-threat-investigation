"""Create an isolated environment, install the tested dependency, and start the UI."""
import argparse
import subprocess
import sys
import venv
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--setup-only', action='store_true')
    args, remaining = parser.parse_known_args()
    root = Path(__file__).resolve().parent
    python = root / '.venv' / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
    if not python.exists():
        print('Creating .venv...', flush=True)
        venv.EnvBuilder(with_pip=True).create(root / '.venv')
    expected = (root / 'requirements.txt').read_text().strip().split('==')[1]
    installed = subprocess.run([str(python), '-c', "import importlib.metadata; print(importlib.metadata.version('cryptography'))"], capture_output=True, text=True)
    if installed.returncode or installed.stdout.strip() != expected:
        subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(root / 'requirements.txt')], check=True)
    if args.setup_only:
        print('Setup complete. Select the .venv interpreter in VS Code and press F5.')
        return
    try:
        raise SystemExit(subprocess.call([str(python), str(root / 'run.py'), *remaining], cwd=root))
    except KeyboardInterrupt:
        pass
if __name__ == '__main__':
    main()
