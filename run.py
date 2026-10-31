"""Project entry point. No editable package installation is required."""
import runpy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))

def main():
    command = sys.argv[1] if len(sys.argv) > 1 else None
    if command == 'test':
        suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if command == 'check':
        sys.argv = [str(ROOT / 'scripts/integration_checks.py')] + sys.argv[2:]
        runpy.run_path(str(ROOT / 'scripts/integration_checks.py'), run_name='__main__')
        return
    if command == 'tamper':
        sys.argv = [str(ROOT / 'scripts/tamper_check.py')] + sys.argv[2:]
        runpy.run_path(str(ROOT / 'scripts/tamper_check.py'), run_name='__main__')
        return
    if command == 'verify-export':
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        from cloud_threat.workflow.exports import main as archive_main
        archive_main()
        return
    if command in ('verify', 'create'):
        from cloud_threat.core.evidence import main as verify_main
        verify_main()
        return
    from cloud_threat.app import main as launch
    launch()
if __name__ == '__main__':
    main()
