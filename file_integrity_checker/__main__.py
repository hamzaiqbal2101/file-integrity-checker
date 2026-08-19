"""Entry point for ``python -m file_integrity_checker``."""

from __future__ import annotations

import sys

from file_integrity_checker.cli import main

if __name__ == "__main__":
    sys.exit(main())