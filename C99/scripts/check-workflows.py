#!/usr/bin/env python3
"""Reject duplicate keys in the GitHub Actions workflow files.

A step with two `env:` blocks is a workflow file GitHub refuses: the run fails
before any job exists, the job list is empty, and the only message is "This run
likely failed because of a workflow file issue". PyYAML's default loader accepts
it silently and keeps the last key, so a plain `yaml.safe_load` check does not
find it -- this one raises on a repeated key instead.

Usage: check-workflows.py [.github/workflows]
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


class StrictLoader(yaml.SafeLoader):
    """A SafeLoader that refuses a mapping with a repeated key."""


def _no_duplicate_keys(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys)


def main(argv):
    root = Path(argv[1]) if len(argv) > 1 else Path(".github/workflows")
    files = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    if not files:
        print(f"workflows: no workflow files under {root}")
        return 0
    failed = 0
    for path in files:
        try:
            yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)
        except yaml.YAMLError as error:
            print(f"workflows: {path}: {error}", file=sys.stderr)
            failed += 1
    if failed:
        print(f"workflows: {failed} file(s) rejected", file=sys.stderr)
        return 1
    print(f"workflows: {len(files)} file(s) parse with no duplicate keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
