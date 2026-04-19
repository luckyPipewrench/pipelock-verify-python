---
name: Bug report
about: A verifier error, mismatch against the Go reference, or unexpected crash
title: ''
labels: bug
assignees: ''
---

## What happened

<!-- Short description. -->

## To reproduce

<!-- Minimal receipt or chain that triggers the issue. Redact signing keys
     if they are production keys. Attach a golden-file-style JSON or JSONL
     if possible. -->

```json
```

## Expected behavior

<!-- What should have happened. -->

## Environment

- `pipelock-verify` version: <!-- e.g. 0.1.0 -->
- Python version: <!-- `python --version` -->
- OS: <!-- e.g. macOS 14, Ubuntu 24.04 -->
- Source of receipt: <!-- Pipelock version / commit the receipt came from -->

## Mismatch vs Go reference?

<!-- If this is a cross-implementation bug, paste the Go CLI output for the
     same input:
       pipelock verify-receipt <file>
     The two implementations should agree byte-for-byte. -->
