# File Integrity Checker

![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white)
![CI](https://img.shields.io/github/actions/workflow/status/hamzaiqbal2101/file-integrity-checker/ci.yml?label=CI)
![Dependencies](https://img.shields.io/badge/dependencies-none-blue)
![Tests](https://img.shields.io/badge/tests-70%20passing-green)
![License](https://img.shields.io/badge/license-MIT-green)

A production-style, modular **File Integrity Verifier (FIM)** built as a
cybersecurity engineering portfolio project. It hashes files in chunks
(constant memory, safe for multi-GB files), stores baselines as JSON
manifests, and detects tampering with CI-friendly exit codes.

This is the *verification* half of a file-integrity monitoring workflow:
you capture a trusted **baseline**, then periodically **verify** that
nothing on disk has changed. Unauthorized modifications, deletions, and
additions are all reported.

This is the second project in a cybersecurity portfolio:

1. [Password Strength Checker](https://github.com/hamzaiqbal2101/password-strength-checker)
2. **File Integrity Checker** (this project)
3. [File Encryptor](https://github.com/hamzaiqbal2101/file-encryptor)
4. [Subdomain Enumerator](https://github.com/hamzaiqbal2101/subdomain-enumerator)
5. [Port Scanner](https://github.com/hamzaiqbal2101/portscanner)

## Features

- **Multiple hash algorithms** - MD5, SHA-1, SHA-256, SHA-512
  (SHA-256 default). See "Algorithm policy" for why MD5/SHA-1 must only be
  used for legacy compatibility.
- **Chunked reading** - files are read in 8 KiB blocks, so memory usage is
  constant regardless of file size.
- **Baseline & verify workflow** - JSON manifest with path, size, hash,
  algorithm, and timestamp; re-hash and compare to detect changes.
- **Five-way classification** - `UNCHANGED`, `MODIFIED`, `MISSING`,
  `NEW`, `UNREADABLE`.
- **Detailed tamper reporting** - old vs new hash for every modified file,
  plus optional report export.
- **Meaningful exit codes** - `0` clean, `1` tampering detected,
  `3` operational error - safe to drive cron jobs and CI/CD gates.
- **Exclusion patterns** - skip `.git`, `__pycache__`, `*.log`, etc.
- **Never silently fails** - unreadable files are recorded in the manifest
  and flagged during verification, never dropped.

## Project structure

```
file_integrity_checker/
  __init__.py     # public API surface
  __main__.py     # enables `python -m file_integrity_checker`
  hashing.py      # chunked hashing + algorithm registry + TOCTOU guard
  scanner.py      # file/dir walking, exclusions, symlink policy, progress
  manifest.py     # JSON schema, atomic writes, validation
  comparator.py   # UNCHANGED/MODIFIED/MISSING/NEW/UNREADABLE logic
  report.py       # console + file report rendering
  cli.py          # baseline / verify subcommands + exit codes
tests/            # pytest suite (68 tests)
sample_data/      # dummy files for demoing the tool
requirements.txt  # no runtime dependencies; pytest for development
```

## Requirements & install

- Python 3.10+
- **No runtime dependencies** - everything used is the standard library
  (`hashlib`, `os`, `json`, `argparse`, `fnmatch`, `tempfile`, `pathlib`).

```bash
pip install -r requirements.txt   # installs pytest (development only)
# or install the CLI as a console command:
pip install -e .
```

## Usage

### 1. Create a baseline

```bash
python -m file_integrity_checker baseline sample_data --recursive
```

Options: `--algorithm {md5,sha1,sha256,sha512}` (default `sha256`),
`--recursive`, `--output manifest.json`, `--exclude PATTERN` (repeatable),
`--chunk-size N`, `--follow-symlinks`.

### 2. Verify against the baseline

```bash
python -m file_integrity_checker verify sample_data --manifest integrity-manifest.json
```

Exit code is `0` when nothing changed and `1` when any change is detected.

### Example - full workflow

```bash
# Baseline the sample data
$ python -m file_integrity_checker baseline sample_data --recursive
Baseline written to integrity-manifest.json: 5 files (sha256).

# Verify (clean)
$ python -m file_integrity_checker verify sample_data --manifest integrity-manifest.json
Result:     NO CHANGES DETECTED
...
Exit code:  0

# Someone tampers with a file...
$ echo "evil" >> sample_data/hello.txt

# Verify (tampered)
$ python -m file_integrity_checker verify sample_data --manifest integrity-manifest.json
Result:     TAMPERING DETECTED

Summary
-------
Total files: 5
UNCHANGED  4
MODIFIED   1
MISSING    0
NEW        0
UNREADABLE 0

Details
-------
[MODIFIED] hello.txt
    old sha256: eec436ba98875cb1ad5bbce1f86142e2a4e4f780b7bda28a04aaa4e6ee6e70ee
    new sha256: a2241b7eafe97dc61dbd577252c99530aae1e22a67393d082beb961c42e18180
    size: 25 -> 36 bytes

Exit code:  1
```

### Example manifest

```json
{
  "manifest_version": 1,
  "generator": "file-integrity-checker/1.0.0",
  "algorithm": "sha256",
  "created_at": "2026-08-19T12:09:24+00:00",
  "base_dir": "sample_data",
  "recursive": true,
  "files": [
    {
      "path": "hello.txt",
      "size": 25,
      "hash": "eec436ba98875cb1ad5bbce1f86142e2a4e4f780b7bda28a04aaa4e6ee6e70ee",
      "error": null
    }
  ]
}
```

Paths are stored **relative to the scanned base** (POSIX separators), so a
manifest remains valid even if the tree is moved to another machine or
directory. Files that could not be hashed at baseline time are recorded
with a non-null `error` field - never silently dropped.

## Design decisions

### Algorithm policy (important)

- **SHA-256** is the default and recommended choice for integrity checking.
- **SHA-512** is provided where a larger digest is mandated.
- **MD5 and SHA-1 are included for legacy compatibility ONLY.** Both are
  broken against collision attacks: an attacker can craft two different
  payloads that produce the same hash. In 2017 the chosen-prefix collision
  of SHA-1 was demonstrated (the SHAttered attack) for under $100k of
  compute; MD5 collisions are trivial to generate. **Do not rely on MD5 or
  SHA-1 for security-critical integrity checks.** They exist here so that
  existing tools, scripts, or compliance checklists that still reference
  them can be serviced - but any new deployment should use SHA-256 or
  SHA-512.

### Chunked reading

Files are read in 8 KiB blocks (`hashlib` updates are incremental), so
memory usage stays flat even for multi-gigabyte files. The digest of a
large file is identical to what you would get by hashing it whole.

### Time-of-check/time-of-use (TOCTOU) guard

A file that is modified *while* it is being read produces a hash matching
neither the old nor the new content. To avoid trusting such an inconsistent
hash, the file size is checked immediately before and after the read; any
mismatch marks the result **unstable** and it is reported as `UNREADABLE`
rather than silently recorded as a good hash.

### Symlink policy

By default, **symlinks are not followed**. Following them would let an
integrity check silently hash files outside the scanned tree and would open
a window for a symlink-swap attack (an attacker redirecting a symlink
between the scan and the hash). Pass `--follow-symlinks` if you
deliberately want them traversed; `os.walk` detects cycles so an infinite
loop cannot occur.

### Atomic manifest writes

Manifests are written to a temporary file in the destination directory and
then renamed into place with `os.replace()`. A crash mid-write can never
leave a truncated or partially-written baseline.

### Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| 0    | Success (baseline complete; verify found no changes)           |
| 1    | Verification detected tampering (MODIFIED/MISSING/NEW/UNREADABLE) |
| 2    | Command-line usage error (argparse)                            |
| 3    | Operational error (missing path, corrupt manifest, unreadable files during baseline) |

`NEW` files are treated as tampering because an integrity *whitelist* is
violated by any unauthorized addition - not just by edits to known files.

## Security notes & tamper-evidence

- The manifest describes files that live on the **same disk**. An attacker
  who can modify the files can usually modify the manifest too. For
  tamper-evidence the manifest should be:
  1. Stored **off-box** (separate host or read-only medium), and/or
  2. **Signed** so any modification is detectable.
- **Future improvement:** add an optional HMAC (shared-secret) or
  asymmetric signature over the manifest body. The on-disk schema already
  reserves room for a `signature` field without a breaking change.
- Verification failures are explicit: a file that cannot be read is
  reported as `UNREADABLE`, never skipped.

## Limitations / what NOT to use this for

- **Not a real-time monitor.** It detects changes only when you run
  `verify`; it cannot prevent tampering or alert instantly. Pair it with a
  scheduler (cron / CI) and off-box log aggregation for a practical
  deployment.
- **Detects content changes, not intent.** A legitimate deployment that
  rewrites config files will produce false positives - manage exclusions
  and re-baseline deliberately after authorized changes.
- **Not a full audit tool.** It does not track permissions, ownership,
  timestamps, or extended attributes (only size + content hash).
- **Hashing speed is I/O-bound** on large trees; for millions of files
  consider sampling, incremental hashing, or a purpose-built FIM (e.g.
  Tripwire, AIDE, osquery).
- **Do not use it as the sole control** for high-value systems - combine it
  with file permission hardening, access logging, and tamper-evident
  storage of the baseline.

## Testing

```bash
python -m pytest
```

68 tests cover chunked hashing and the TOCTOU guard, scanning and
exclusions, symlink policy, manifest round-trips and corruption handling,
comparison logic (all five statuses), report rendering, and end-to-end CLI
behavior including exit codes. Two symlink tests auto-skip on platforms
without symlink support.

## License

MIT - see `LICENSE`. This is an educational portfolio project.