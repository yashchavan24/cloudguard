"""
Terraform parser: walks a directory of .tf files and yields
(resource_type, resource_name, config_dict, source_file) tuples
that the rule engine can check.

Uses python-hcl2 to get real HCL parsing (handles multi-line blocks,
nested attributes, etc.) rather than a naive regex/line-scanner.
"""
import os
import hcl2
from pathlib import Path


def _strip_quotes(s: str) -> str:
    if isinstance(s, str) and len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _normalize(value):
    """
    python-hcl2 (this version) leaves literal quote characters on plain
    string tokens instead of resolving them, e.g. 'acl' -> '"public-read"'
    instead of 'public-read'. Recursively strip those so the rule engine
    can compare against plain values like "public-read" / "*" / etc.
    """
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items() if k not in ("__comments__",)}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return _strip_quotes(value)
    return value


def find_tf_files(root_path: str):
    root = Path(root_path)
    if root.is_file() and root.suffix == ".tf":
        return [root]
    return sorted(root.rglob("*.tf"))


def parse_tf_file(path: Path):
    """Parse a single .tf file, return list of (resource_type, name, config)."""
    resources = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            parsed = hcl2.load(f)
    except Exception as e:
        # Malformed HCL shouldn't crash the whole scan
        return [], str(e)

    for block in parsed.get("resource", []):
        # block looks like {"aws_s3_bucket": {"my_bucket": {...attrs...}}}
        for resource_type, named in block.items():
            resource_type = _strip_quotes(resource_type)
            for name, attrs in named.items():
                name = _strip_quotes(name)
                resources.append((resource_type, name, _normalize(attrs)))
    return resources, None


def parse_terraform_directory(root_path: str):
    """
    Yields (resource_type, resource_name, config, source_file, parse_error)
    for every resource block found under root_path.
    """
    results = []
    errors = []
    for tf_file in find_tf_files(root_path):
        resources, error = parse_tf_file(tf_file)
        if error:
            errors.append((str(tf_file), error))
            continue
        for resource_type, name, attrs in resources:
            results.append((resource_type, name, attrs, str(tf_file)))
    return results, errors
