"""Allow `python3 -m redact ...` to work in addition to the `redact` entry point."""

import sys

from .cli import main

if __name__ == '__main__':
    sys.exit(main())
