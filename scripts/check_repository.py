"""Check repository naming, syntax, configuration and prohibited artifacts."""
import ast
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Assemble the retired identifier without introducing it into repository content.
RETIRED_IDENTIFIER = ''.join(chr(code) for code in (100, 101, 109, 111))
EXCLUDED = {'.git', '.venv', '__pycache__', 'runs', 'workspace', 'dist', 'build'}
TEXT_SUFFIXES = {'.py', '.md', '.html', '.css', '.js', '.json', '.jsonl', '.toml', '.yml', '.bat', '.sh', '.code-workspace', '.mjs'}

def main() -> None:
    failures = []
    for path in ROOT.rglob('*'):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED or part.endswith('.egg-info') for part in relative.parts):
            continue
        if RETIRED_IDENTIFIER in str(relative).lower():
            failures.append(f'Retired identifier in path: {relative}')
        if not path.is_file():
            continue
        if path.name == 'signing-key.bin' or path.suffix in {'.pem', '.key', '.p12', '.pfx', '.pyc'}:
            failures.append(f'Excluded artifact: {relative}')
        if path.suffix not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding='utf8')
        if RETIRED_IDENTIFIER in text.lower():
            failures.append(f'Retired identifier in content: {relative}')
        if ('-----BEGIN ' + 'PRIVATE KEY-----') in text:
            failures.append(f'Private key material: {relative}')
        if path.suffix == '.py':
            ast.parse(text, filename=str(relative))
        if path.suffix == '.json' or path.suffix == '.code-workspace':
            json.loads(text)
        if path.suffix == '.toml':
            tomllib.loads(text)
    if failures:
        raise SystemExit('\n'.join(failures))
    print('Repository checks passed: naming, Python syntax, configuration and artifact hygiene.')

if __name__ == '__main__':
    main()
