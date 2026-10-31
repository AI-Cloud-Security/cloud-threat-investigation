"""Case creation and command-line evidence verification."""
import argparse
import json
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .canonical import canonical
from .provenance import build
from .signing import seal, verify
from .validation import parse_record
RESOURCE_ROOT = Path(__file__).resolve().parents[1] / 'resources'

def load_events(path: str | Path) -> list[bytes]:
    """Read bounded JSONL input, preserving each record's original bytes."""
    path = Path(path)
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Input file exceeds the 16 MiB limit')
    return [line for line in path.read_bytes().splitlines() if line.strip()]

def create_case(output: str | Path, events_path: str | Path | None=None, policy_path: str | Path | None=None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate, verify and exclusively publish a software-signed case.

    A failed write removes only artifacts created by this invocation. Existing
    artifacts are never overwritten. This behavior does not enforce retention.
    """
    events_file = Path(events_path) if events_path else RESOURCE_ROOT / 'sample_events.jsonl'
    policy_file = Path(policy_path) if policy_path else RESOURCE_ROOT / 'policy.json'
    graph, decision, attribution, scenario = build(load_events(events_file), parse_record(policy_file.read_bytes()))
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    bundle = seal(graph, signing_key)
    verification = verify(bundle, public_key)
    summary = {'decision': decision, 'attribution': attribution, 'counterfactual': scenario, 'verification': verification}
    artifacts = {'bundle.json': canonical(bundle), 'trusted_public_key.bin': public_key, 'summary.json': canonical(summary)}
    target = Path(output)
    target.mkdir(parents=True, exist_ok=True)
    if any(((target / name).exists() for name in artifacts)):
        raise FileExistsError('Output contains existing case artifacts; use a new directory')
    created: list[Path] = []
    try:
        for name, content in artifacts.items():
            destination = target / name
            with destination.open('xb') as stream:
                created.append(destination)
                stream.write(content)
    except OSError:
        for destination in reversed(created):
            destination.unlink(missing_ok=True)
        raise
    return (bundle, summary)

def main() -> None:
    """Provide explicit case creation and trusted-key verification commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--out', required=True)
    create.add_argument('--events')
    create.add_argument('--policy')
    check = commands.add_parser('verify')
    check.add_argument('bundle')
    check.add_argument('--trusted-key', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'create':
            result = create_case(args.out, args.events, args.policy)[1]
        else:
            result = verify(parse_record(Path(args.bundle).read_bytes(), max_bytes=64 * 1024 * 1024), Path(args.trusted_key).read_bytes())
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f'Operation failed: {error}\n')
    except Exception as error:
        parser.exit(1, f'Verification rejected: {type(error).__name__}\n')
    print(json.dumps(result, indent=2))
if __name__ == '__main__':
    main()
