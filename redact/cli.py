"""Command-line interface for redact."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import redact_text


def process_file(path: Path, extra_domains, to_stdout: bool, suffix: str) -> bool:
    try:
        original = path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        print(f"[error] could not read {path}: {e}", file=sys.stderr)
        return False

    redacted = redact_text(original, extra_domains)

    if to_stdout:
        sys.stdout.write(redacted)
        return True

    out_path = path.with_name(path.name + suffix)
    try:
        out_path.write_text(redacted, encoding='utf-8')
    except Exception as e:
        print(f"[error] could not write {out_path}: {e}", file=sys.stderr)
        return False

    print(f"[ok] {path} -> {out_path}")
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='redact',
        description=(
            "Redact IPs, hostnames, MACs, emails and credentials from text "
            "files (logs, configs) before sharing them publicly (bug "
            "reports, support tickets, etc)."
        ),
    )
    parser.add_argument('files', nargs='+', help='File(s) to redact')
    parser.add_argument(
        '--domain', action='append', default=[],
        help='Additional client domain to redact (repeatable)',
    )
    parser.add_argument(
        '--stdout', action='store_true',
        help='Print the result to stdout instead of writing a .redacted file',
    )
    parser.add_argument(
        '--suffix', default='.redacted',
        help='Output file suffix (default: .redacted)',
    )
    parser.add_argument(
        '--version', action='version', version=f'redact {__version__}',
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ok_all = True
    for f in args.files:
        path = Path(f)
        if not path.exists():
            print(f"[error] file not found: {f}", file=sys.stderr)
            ok_all = False
            continue
        ok = process_file(path, args.domain, args.stdout, args.suffix)
        ok_all = ok_all and ok

    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main())
