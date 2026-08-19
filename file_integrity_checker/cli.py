"""Command-line interface for the file integrity checker.

Two subcommands:

* ``baseline`` - hash a file/directory and write a JSON manifest.
* ``verify``   - re-hash the same target and compare against the manifest.

Exit codes (designed for CI/CD and cron integration):

* 0 - success (baseline written cleanly; verify found no changes)
* 1 - verify detected tampering (MODIFIED / MISSING / NEW / UNREADABLE)
* 2 - command-line usage error (argparse)
* 3 - operational error (missing path, corrupt manifest, unreadable files
      during baseline)

Progress and warnings are written to stderr so stdout stays clean for the
report and safe to pipe or redirect.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from file_integrity_checker import __version__
from file_integrity_checker.comparator import ComparisonResult, compare
from file_integrity_checker.hashing import CHUNK_SIZE, DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS
from file_integrity_checker.manifest import (
    DEFAULT_MANIFEST_NAME,
    ManifestError,
    build_manifest,
    read_manifest,
    write_manifest,
)
from file_integrity_checker.report import export_report, render_report
from file_integrity_checker.scanner import scan_files

_PROG = "file-integrity-checker"
_GENERATOR = f"{_PROG}/{__version__}"

EXIT_OK = 0
EXIT_TAMPERED = 1
EXIT_ERROR = 3

_PROGRESS_INTERVAL = 100


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command-line parser.

    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "Create and verify file integrity baselines. Hashes files in "
            "chunks (constant memory) and reports UNCHANGED, MODIFIED, "
            "MISSING, NEW, and UNREADABLE files. Exits non-zero when "
            "tampering is detected."
        ),
        epilog=(
            "Examples:\n"
            f"  {_PROG} baseline sample_data --recursive\n"
            f"  {_PROG} verify sample_data --manifest integrity-manifest.json\n"
            f"  {_PROG} baseline . --recursive --exclude .git --exclude '*.tmp'\n"
            "  Use --algorithm sha512 for a stronger digest, or md5/sha1 "
            "for legacy compatibility only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser(
        "baseline",
        help="hash a file/directory and write a manifest",
        description="Hash a file or directory and save the result as a JSON manifest.",
    )
    baseline.add_argument(
        "path",
        nargs="?",
        default=".",
        help="file or directory to hash (default: current directory)",
    )
    baseline.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default=DEFAULT_ALGORITHM,
        help=f"hash algorithm (default: {DEFAULT_ALGORITHM})",
    )
    baseline.add_argument(
        "--recursive",
        action="store_true",
        help="recurse into subdirectories when hashing a directory",
    )
    baseline.add_argument(
        "--output",
        default=DEFAULT_MANIFEST_NAME,
        help=f"manifest output path (default: {DEFAULT_MANIFEST_NAME})",
    )
    baseline.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "skip files/directories matching a fnmatch pattern; repeatable "
            "(e.g. --exclude .git --exclude '*.log')"
        ),
    )
    baseline.add_argument(
        "--chunk-size",
        type=int,
        default=CHUNK_SIZE,
        help=f"read buffer size in bytes (default: {CHUNK_SIZE})",
    )
    baseline.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symlinks while scanning (default: skip them)",
    )
    baseline.set_defaults(handler=_cmd_baseline)

    verify = subparsers.add_parser(
        "verify",
        help="re-hash and compare against a manifest",
        description=(
            "Re-hash a file/directory and compare the result against a "
            "baseline manifest. Exits with code 1 if any changes are found."
        ),
    )
    verify.add_argument(
        "path",
        nargs="?",
        default=None,
        help="file or directory to verify (default: manifest base_dir)",
    )
    verify.add_argument(
        "--manifest",
        required=True,
        help=f"path to the baseline manifest (default filename: {DEFAULT_MANIFEST_NAME})",
    )
    verify.add_argument(
        "--output",
        metavar="REPORT",
        help="also export the full report to this file",
    )
    verify.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "skip files/directories matching a fnmatch pattern; repeatable. "
            "Must mirror the baseline excludes to avoid spurious NEW files."
        ),
    )
    verify.add_argument(
        "--chunk-size",
        type=int,
        default=CHUNK_SIZE,
        help=f"read buffer size in bytes (default: {CHUNK_SIZE})",
    )
    verify.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symlinks while scanning (default: skip them)",
    )
    verify.set_defaults(handler=_cmd_verify)

    return parser


def _make_progress() -> Callable[[int], None]:
    """Create a progress callback that reports to stderr every N files."""

    def on_progress(count: int) -> None:
        if count % _PROGRESS_INTERVAL == 0:
            print(f"Processed {count} files...", file=sys.stderr)

    return on_progress


def _cmd_baseline(args: argparse.Namespace) -> int:
    """Run the ``baseline`` subcommand.

    Args:
        args: Parsed namespace (requires ``path``, ``algorithm``,
            ``recursive``, ``output``, ``exclude``, ``chunk_size``,
            ``follow_symlinks``).

    Returns:
        ``EXIT_OK`` on a complete baseline, ``EXIT_ERROR`` when the target
        does not exist or some files could not be hashed (the manifest is
        still written so the failure is inspectable, never silent).
    """
    target = Path(args.path)
    if not target.exists():
        print(f"[!] Path does not exist: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    results, warnings = scan_files(
        args.path,
        algorithm=args.algorithm,
        recursive=args.recursive,
        excludes=args.exclude,
        follow_symlinks=args.follow_symlinks,
        chunk_size=args.chunk_size,
        on_progress=_make_progress(),
    )
    for warning in warnings:
        print(f"[!] {warning}", file=sys.stderr)

    manifest = build_manifest(
        algorithm=args.algorithm,
        base_dir=str(target),
        recursive=args.recursive,
        scan_results=results,
        generator=_GENERATOR,
    )
    write_manifest(manifest, args.output)

    print(f"Baseline written to {args.output}: {len(manifest.entries)} files ({args.algorithm}).")

    unreadable = [entry.path for entry in manifest.entries if entry.error]
    if unreadable:
        print(
            f"[!] {len(unreadable)} file(s) could not be hashed and were "
            "recorded in the manifest as unreadable.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    """Run the ``verify`` subcommand.

    Args:
        args: Parsed namespace (requires ``manifest``, optional ``path``,
            ``output``, ``exclude``, ``chunk_size``, ``follow_symlinks``).

    Returns:
        ``EXIT_OK`` when nothing changed, ``EXIT_TAMPERED`` when any change
        was detected, or ``EXIT_ERROR`` for operational failures (missing
        manifest, corrupt manifest, missing target).
    """
    try:
        manifest = read_manifest(args.manifest)
    except ManifestError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return EXIT_ERROR

    target = args.path or manifest.base_dir
    if not Path(target).exists():
        print(f"[!] Target path does not exist: {target}", file=sys.stderr)
        return EXIT_ERROR

    # The manifest itself is commonly stored inside the tree it verifies.
    # Exclude it automatically so it is not reported as a NEW file on every
    # verification.
    excludes = list(args.exclude)
    manifest_path = Path(args.manifest)
    try:
        manifest_abs = manifest_path.resolve()
        target_abs = Path(target).resolve()
        if manifest_abs.is_relative_to(target_abs):
            excludes.append(manifest_abs.relative_to(target_abs).as_posix())
    except OSError:
        pass

    results, warnings = scan_files(
        target,
        algorithm=manifest.algorithm,
        recursive=manifest.recursive,
        excludes=excludes,
        follow_symlinks=args.follow_symlinks,
        chunk_size=args.chunk_size,
        on_progress=_make_progress(),
    )
    for warning in warnings:
        print(f"[!] {warning}", file=sys.stderr)

    result: ComparisonResult = compare(manifest, results)
    report_text = render_report(result, args.manifest, manifest.base_dir)
    print(report_text)

    if args.output:
        export_report(result, args.output, args.manifest, manifest.base_dir)
        print(f"Report exported to {args.output}")

    return EXIT_TAMPERED if result.has_changes else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (see module docstring for the scheme).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)