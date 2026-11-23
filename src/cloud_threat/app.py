"""Start the persistent local investigation workspace."""
import argparse
import logging
import webbrowser
from pathlib import Path

from cloud_threat.web.application import make_application


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path.cwd() / 'workspace',
                        help='Persistent database and local signing identity directory')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Bind address. Keep the loopback default unless running inside a container.')
    parser.add_argument('--allowed-host', action='append', default=[], metavar='HOST:PORT',
                        help='Additional Host header value to accept, e.g. localhost:9000 for a remapped container port')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    try:
        server = make_application(args.workspace, args.port, args.host, tuple(args.allowed_host))
        if args.host not in ('127.0.0.1', 'localhost', '::1'):
            print(f'WARNING: listening on {args.host}. Publish the port to loopback only '
                  '(e.g. docker run -p 127.0.0.1:8765:8765). This is a single-user workspace without login.', flush=True)
    except (ValueError, OSError) as error:
        parser.exit(1, f'Workspace startup failed: {error}\n')
    url = f'http://127.0.0.1:{server.server_port}'
    print(f'Workspace: {args.workspace.resolve()}', flush=True)
    print(f'Open {url} (Ctrl+C to stop)', flush=True)
    print('Import normalized security records in the browser to begin an investigation.', flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nInvestigation service stopped. Your cases remain in the workspace.')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
