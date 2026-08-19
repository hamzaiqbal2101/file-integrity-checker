# Sample data for demoing the File Integrity Checker

These dummy files let you try the tool without touching any real data.

```bash
# Create a baseline of this folder (recursively)
python -m file_integrity_checker baseline sample_data --recursive

# Verify it (should report NO CHANGES DETECTED, exit 0)
python -m file_integrity_checker verify sample_data --manifest integrity-manifest.json

# Tamper with a file, then verify again (should report TAMPERING DETECTED, exit 1)
```

Files:

- `hello.txt` - a plain text file
- `nested/note.txt` - a file in a subdirectory (exercises recursion)
- `nested/config.json` - a small JSON file
- `scratch.log` - a log-style file, useful for demonstrating `--exclude '*.log'`