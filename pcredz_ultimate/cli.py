from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

from .capture import live_capture
from .engine import AuditEngine, capture_files_in_directory


VERSION = '3.1.0'
BANNER = r'''
 ____   ____              _        _   _ _ _   _                 _       
|  _ \ / ___|_ __ ___  __| |____  | | | | | |_(_)_ __ ___   __ _| |_ ___ 
| |_) | |   | '__/ _ \/ _` |_  /  | | | | | __| | '_ ` _ \ / _` | __/ _ \
|  __/| |___| | |  __/ (_| |/ /   | |_| | | |_| | | | | | | (_| | ||  __/
|_|    \____|_|  \___|\__,_/___|    \___/|_|\__|_|_| |_| |_|\__,_|\__\___|
'''


def _split_csv(values: list[str] | None) -> list[str]:
    result: list[str] = []
    for value in values or []:
        result.extend(item.strip() for item in value.split(',') if item.strip())
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='Pcredz',
        description=(
            'Passive network credential and authentication-material auditing for authorized captures. '
            'Secrets are redacted by default.'
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('-f', '--file', action='append', help='PCAP/PCAPNG file; repeat for multiple captures')
    source.add_argument('-d', '--directory', help='Recursively process capture files in a directory')
    source.add_argument('-i', '--interface', help='Capture passively from a local interface')

    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--reveal-secrets', action='store_true',
                        help='Write full recovered secrets to reports and console')
    parser.add_argument('--export-hashes', action='store_true',
                        help='Export supported challenge-response material to hashes/ (no cracking performed)')
    parser.add_argument('--no-html', action='store_true', help='Do not generate report.html')
    parser.add_argument('--overwrite-output', action='store_true',
                        help='Delete and recreate a non-empty output directory')
    parser.add_argument('--disable', action='append', default=[],
                        help='Comma-separated detector/protocol/category names to disable')
    parser.add_argument('--exclude-host', action='append', default=[],
                        help='Exclude an IP, hostname, or CIDR; repeat as needed')
    parser.add_argument('--max-stream-bytes', type=int, default=4 * 1024 * 1024,
                        help='Per-detector/reassembly buffer limit')
    parser.add_argument('--snaplen', type=int, default=262144, help='Live-capture snapshot length')
    parser.add_argument('--live-authorized', action='store_true',
                        help='Acknowledge that live capture is authorized for this interface/network')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose diagnostics and retain duplicate findings')
    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='Compatibility option; timestamps are always included')
    parser.add_argument('--threads', type=int, default=1,
                        help='Compatibility option; deterministic parser currently runs single-threaded')
    parser.add_argument('-c', '--no-card-scan', action='store_true',
                        help='Compatibility option; payment-card scanning is intentionally not included')
    parser.add_argument('--quiet-banner', action='store_true', help='Suppress startup banner')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.quiet_banner:
        print(BANNER)
        print(f'PCredz Ultimate {VERSION} — passive authorized auditing; secrets redacted by default.\n')

    if args.max_stream_bytes < 64 * 1024:
        parser.error('--max-stream-bytes must be at least 65536')
    if args.interface and not args.live_authorized:
        parser.error('live capture requires --live-authorized')
    if args.threads != 1:
        print('[note] --threads is retained for compatibility; parsing remains deterministic and single-threaded.')
    if args.reveal_secrets:
        print('[warning] Full recovered secrets will be written to disk and printed to the console.')
    if args.export_hashes:
        print('[warning] Full supported authentication material will be exported under hashes/.')

    output = args.output or f'PCredz-Ultimate-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
    output_path = Path(output)
    if output_path.exists() and any(output_path.iterdir()):
        if not args.overwrite_output:
            parser.error(f'output directory is not empty: {output} (use --overwrite-output)')
        shutil.rmtree(output_path)
    disabled = _split_csv(args.disable)
    engine = AuditEngine(
        output,
        reveal_secrets=args.reveal_secrets,
        export_hashes=args.export_hashes,
        write_html=not args.no_html,
        verbose=args.verbose,
        disabled=disabled,
        excluded_hosts=args.exclude_host,
        max_stream_bytes=args.max_stream_bytes,
    )

    try:
        if args.file:
            for path in args.file:
                if not Path(path).is_file():
                    parser.error(f'capture file not found: {path}')
                print(f'[*] Processing {path}')
                engine.process_capture(path)
        elif args.directory:
            files = capture_files_in_directory(args.directory)
            if not files:
                parser.error(f'no PCAP/PCAPNG files found under: {args.directory}')
            print(f'[*] Processing {len(files)} capture file(s) from {args.directory}')
            for path in files:
                print(f'[*] Processing {path}')
                engine.process_capture(path)
        else:
            print(f'[*] Live passive capture on {args.interface}; press Ctrl-C to stop and finalize.')
            packets = live_capture(args.interface, snaplen=args.snaplen)
            try:
                engine.process_capture_packets(packets, label=f'live:{args.interface}')
            except KeyboardInterrupt:
                print('\n[*] Capture stopped by operator.')
    except KeyboardInterrupt:
        print('\n[*] Interrupted; finalizing partial results.')
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'[error] {exc}', file=sys.stderr)
        return 2
    finally:
        try:
            engine.finalize()
        except Exception as exc:
            print(f'[error] could not finalize output: {exc}', file=sys.stderr)
            return 2

    print(f'\n[+] Audit complete: {Path(output).resolve()}')
    print(f'[+] Findings: {engine.stats.get("findings_written", 0)}')
    print('[+] Open report.html or query audit.sqlite for the full audit trail.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
