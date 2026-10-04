#!/usr/bin/env python3
"""Validate project extensions and run one explicitly selected check phase."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def load_config(root):
    path = root / ".factory/project/config.json"
    config = json.loads(path.read_text())
    keys = {"schema_version", "verification_commands", "pre_commit_commands"}
    if not isinstance(config, dict) or set(config) != keys:
        raise ValueError(f"{path}: expected exactly {sorted(keys)}")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("unsupported project configuration schema_version")
    for key in keys - {"schema_version"}:
        commands = config[key]
        if not isinstance(commands, list):
            raise ValueError(f"{key} must be a list of argument arrays")
        for command in commands:
            if not isinstance(command, list) or not command or any(
                not isinstance(arg, str) or not arg or "\0" in arg for arg in command
            ):
                raise ValueError(f"{key}: each command must be a nonempty string array")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["config", "verify", "pre-commit"])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    try:
        config = load_config(root)
        if args.phase == "config":
            print("Factory project configuration is valid.")
            return 0
        key = "verification_commands" if args.phase == "verify" else "pre_commit_commands"
        if args.phase == "verify" and not config[key]:
            raise ValueError("verification is unconfigured; select project commands first")
        for command in config[key]:
            print(f"Running {command!r}", flush=True)
            result = subprocess.run(command, cwd=root, check=False)
            if result.returncode:
                return result.returncode if result.returncode > 0 else 1
        return 0
    except (OSError, ValueError) as exc:
        print(f"Factory check: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
