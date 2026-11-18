#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Show how the fields of a finding map to OCSF, using the mapping tables in this repository.

This script is an illustration of the mapping tables. It is not a supported converter and does
not produce complete or validated OCSF findings. AWS Security Hub produces the authoritative OCSF
findings.

For each mapping row whose source field has a value in the input finding, the script prints the
source path, the value, the OCSF path and the transform. Rows with transform `direct` are copied
into a partial OCSF finding. Rows with transform `converted` are listed but not computed, because
the conversion is not described in the tables.

Usage:
  python3 sample/convert.py --source guardduty FILE
  python3 sample/convert.py --source security-hub-cspm FILE
  python3 sample/convert.py --source inspector FILE
  python3 sample/convert.py --source guardduty --json FILE      print the partial OCSF finding as JSON
  python3 sample/convert.py --source guardduty --index 0 FILE   process only one finding of the file

FILE may hold a single finding, an API or CLI response ({"Findings": [...]} or {"findings": [...]}),
or an Amazon EventBridge event whose `detail` holds the finding.

Exit codes: 0 success, 1 invalid input, 2 usage error.
"""
import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = ROOT / "mappings"

MAX_INPUT_BYTES = 5 * 1024 * 1024

SOURCES = {
    "guardduty": {"directory": "guardduty", "csv": "guardduty-to-ocsf.csv", "column": "guardduty_field"},
    "security-hub-cspm": {"directory": "security-hub-cspm", "csv": "asff-to-ocsf.csv", "column": "asff_field"},
    "inspector": {"directory": "inspector", "csv": "inspector-to-ocsf.csv", "column": "inspector_field"},
}

# Paths whose value is a JSON-encoded string that is decoded before the rest of the path is read.
JSON_STRING_PATHS = {"guardduty": ["service", "additionalInfo", "value"]}

# Map types whose keys may contain dots and other separators: the rest of the path is one key.
OPAQUE_MAPS = {"security-hub-cspm": ["ProductFields"]}

# Area conditions stated precisely in the source READMEs and evaluated here.
CSPM_PROVIDER_AREAS = {"AWS Resource": None, "Azure Resource": "azure"}
INSPECTOR_TYPE_AREAS = {
    "Package Vulnerability": "PACKAGE_VULNERABILITY",
    "Code Vulnerability": "CODE_VULNERABILITY",
    "Network Reachability": "NETWORK_REACHABILITY",
}
# Inspector resource areas apply when resources[0].details holds the matching object.
INSPECTOR_DETAIL_AREAS = {
    "EC2 Instance": "awsEc2Instance",
    "Other VM": "vm",
    "ECR Container Image": "awsEcrContainerImage",
    "Other Container Image": "image",
    "Lambda Function": "awsLambdaFunction",
    "Other Serverless Function": "serverlessFunction",
}
INSPECTOR_FINDING_TYPES_WITH_RESOURCE_DETAILS = {"PACKAGE_VULNERABILITY", "CODE_VULNERABILITY"}

SEGMENT = re.compile(r"^(?P<key>[^\[\]]+)(?P<index>\[(?:\d*)\])?$")


class InputError(Exception):
    """The input file cannot be read as findings."""


def load_rows(source_name):
    source = SOURCES[source_name]
    path = MAPPINGS / source["directory"] / source["csv"]
    with path.open(newline="", encoding="utf-8") as fh:
        return [dict(row, source_field=row[source["column"]]) for row in csv.DictReader(fh)]


def read_input(path):
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from None
    if size > MAX_INPUT_BYTES:
        raise InputError(f"{path} is {size} bytes; files over {MAX_INPUT_BYTES} bytes are refused")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except UnicodeDecodeError:
        raise InputError(f"{path} is not UTF-8 text") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}") from None
    except RecursionError:
        raise InputError(f"{path} is nested too deeply") from None
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from None


def extract_findings(document):
    """Return the findings in a single finding, an API/CLI response or an EventBridge event."""
    if isinstance(document, dict):
        for key in ("Findings", "findings"):
            if isinstance(document.get(key), list):
                return [f for f in document[key] if isinstance(f, dict)]
        detail = document.get("detail")
        if isinstance(detail, dict) and ("detail-type" in document or "source" in document):
            return extract_findings(detail)
        return [document]
    if isinstance(document, list):
        return [f for f in document if isinstance(f, dict)]
    raise InputError("the input is not a JSON object or array")


def get_key(mapping, key):
    """Look a key up case-insensitively (exact match first)."""
    if key in mapping:
        return mapping[key], True
    lowered = key.lower()
    for candidate, value in mapping.items():
        if isinstance(candidate, str) and candidate.lower() == lowered:
            return value, True
    return None, False


def decode_json_string(value):
    try:
        return json.loads(value)
    except (ValueError, RecursionError):
        return None


def parse_path(path):
    """Split a mapping path into (key, index) segments. index is None, '[]' or an integer."""
    segments = []
    for part in path.split("."):
        if part == "*":
            segments.append(("*", None))
            continue
        match = SEGMENT.match(part)
        if not match:
            segments.append((part, None))
            continue
        index = match.group("index")
        if index is None:
            segments.append((match.group("key"), None))
        elif index == "[]":
            segments.append((match.group("key"), "[]"))
        else:
            segments.append((match.group("key"), int(index[1:-1])))
    return segments


def resolve(finding, source_name, path):
    """Return a list of (indexes, value, map_key) for every value at the path.

    indexes holds one entry per `[]` or `*` in the path, so values can be placed in OCSF arrays.
    """
    opaque = OPAQUE_MAPS.get(source_name, [])
    json_path = JSON_STRING_PATHS.get(source_name)
    parts = path.split(".")
    if opaque and parts[0] in opaque and len(parts) > 1:
        segments = [(parts[0], None), (".".join(parts[1:]), None)]
    else:
        segments = parse_path(path)

    results = []

    def walk(node, position, indexes, map_key, trail):
        if position == len(segments):
            if node is not None and node != "" and node != [] and node != {}:
                results.append((indexes, node, map_key))
            return
        key, index = segments[position]
        if isinstance(node, str) and json_path and [k.lower() for k in trail] == [k.lower() for k in json_path]:
            node = decode_json_string(node)
        if key == "*":
            if isinstance(node, dict):
                for i, (k, v) in enumerate(node.items()):
                    walk(v, position + 1, indexes + (i,), k, trail + [k])
            return
        if not isinstance(node, dict):
            return
        value, found = get_key(node, key)
        if not found:
            return
        if index is None:
            walk(value, position + 1, indexes, map_key, trail + [key])
        elif index == "[]":
            if isinstance(value, list):
                for i, item in enumerate(value):
                    walk(item, position + 1, indexes + (i,), map_key, trail + [key])
        elif isinstance(value, list) and index < len(value):
            walk(value[index], position + 1, indexes, map_key, trail + [key])

    walk(finding, 0, (), None, [])
    return results


def area_applies(source_name, area, finding):
    """Evaluate the area conditions that the source READMEs state precisely. Others always apply."""
    if source_name == "security-hub-cspm" and area in CSPM_PROVIDER_AREAS:
        providers = {str(v).lower() for _, v, _ in resolve(finding, source_name, "Resources[].Provider")}
        wanted = CSPM_PROVIDER_AREAS[area]
        if wanted is None:
            return "azure" not in providers
        return wanted in providers
    if source_name == "inspector":
        types = {v for _, v, _ in resolve(finding, source_name, "type")}
        if area in INSPECTOR_TYPE_AREAS:
            return INSPECTOR_TYPE_AREAS[area] in types
        details = resolve(finding, source_name, "resources[0].details")
        present = set(details[0][1]) if details and isinstance(details[0][1], dict) else set()
        present_lower = {k.lower() for k in present}
        if area in INSPECTOR_DETAIL_AREAS:
            if area != "EC2 Instance" and area != "Other VM" and not types & INSPECTOR_FINDING_TYPES_WITH_RESOURCE_DETAILS:
                return False
            if area == "Other VM" and "awsec2instance" in present_lower:
                return False
            if area == "Other Container Image" and "awsecrcontainerimage" in present_lower:
                return False
            if area == "Other Serverless Function" and "awslambdafunction" in present_lower:
                return False
            return INSPECTOR_DETAIL_AREAS[area].lower() in present_lower
        if area == "Other Resource Types":
            known = {v.lower() for v in INSPECTOR_DETAIL_AREAS.values()}
            return bool(types & INSPECTOR_FINDING_TYPES_WITH_RESOURCE_DETAILS) and not present_lower & known
    return True


def set_ocsf(document, path, indexes, value):
    """Write value at an OCSF path. `[]` positions take indexes in order (0 when there are none left).

    Returns False when the location already holds a value (the first value is kept).
    """
    segments = parse_path(path)
    queue = list(indexes)
    # Leading OCSF arrays with no matching source index use element 0.
    array_count = sum(1 for _, index in segments if index == "[]")
    while len(queue) < array_count:
        queue.insert(0, 0)
    queue = queue[len(queue) - array_count:] if array_count else []

    node = document
    for position, (key, index) in enumerate(segments):
        last = position == len(segments) - 1
        if index is None:
            if last:
                if key in node:
                    return False
                node[key] = value
                return True
            node = node.setdefault(key, {})
            continue
        items = node.setdefault(key, [])
        slot = queue.pop(0) if index == "[]" else index
        while len(items) <= slot:
            items.append({} if not last else None)
        if last:
            if items[slot] is not None:
                return False
            items[slot] = value
            return True
        if items[slot] is None:
            items[slot] = {}
        node = items[slot]
    return True


def convert(finding, source_name, rows):
    applied, not_computed, conflicts = [], [], []
    partial = {}
    for row in rows:
        if not area_applies(source_name, row["area"], finding):
            continue
        source_path = row["source_field"]
        if source_name == "security-hub-cspm" and source_path.startswith("evaluationResult."):
            not_computed.append((row, "not in finding"))
            continue
        for indexes, value, map_key in resolve(finding, source_name, source_path):
            if source_path.endswith(".*") and row["ocsf_field"].endswith(".name"):
                value = map_key
            if row["transform"] == "direct":
                written = set_ocsf(partial, row["ocsf_field"], indexes, value)
                applied.append((row, value))
                if not written:
                    conflicts.append((row, value))
            else:
                not_computed.append((row, "converted"))
                break
    return partial, applied, not_computed, conflicts


def short(value, limit=60):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def print_trace(applied, not_computed, conflicts, out):
    out.write("Applied mappings (source path -> value -> OCSF path -> transform)\n")
    for row, value in applied:
        out.write(f"  {row['source_field']} -> {short(value)} -> {row['ocsf_field']} -> {row['transform']}\n")
    if not applied:
        out.write("  (none)\n")
    out.write("\nNot computed (the source field has a value, but its conversion is not described in the tables)\n")
    seen = set()
    for row, reason in not_computed:
        key = (row["source_field"], row["ocsf_field"])
        if key in seen:
            continue
        seen.add(key)
        out.write(f"  {row['source_field']} -> {row['ocsf_field']} ({reason})\n")
    if not seen:
        out.write("  (none)\n")
    if conflicts:
        out.write("\nNot written to the partial finding because another row already set the same OCSF field\n")
        for row, value in conflicts:
            out.write(f"  {row['source_field']} -> {short(value)} -> {row['ocsf_field']}\n")


def finding_id(finding):
    for key in ("id", "Id", "findingArn", "arn", "Arn"):
        value, found = get_key(finding, key)
        if found and isinstance(value, str):
            return value
    return "(no id)"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Show how a finding's fields map to OCSF (illustrative only).")
    parser.add_argument("--source", required=True, choices=sorted(SOURCES), help="format of the input finding")
    parser.add_argument("--json", action="store_true", help="print the partial OCSF finding as JSON")
    parser.add_argument("--index", type=int, help="process only the finding at this position (from 0)")
    parser.add_argument("file", help="JSON file holding one or more findings")
    args = parser.parse_args(argv)

    try:
        findings = extract_findings(read_input(args.file))
        if not findings:
            raise InputError("no findings in the input")
        selected = list(enumerate(findings))
        if args.index is not None:
            if not 0 <= args.index < len(findings):
                raise InputError(f"--index {args.index} is out of range; the input holds {len(findings)} finding(s)")
            selected = [(args.index, findings[args.index])]
        rows = load_rows(args.source)
        results = []
        for position, finding in selected:
            results.append((position, finding, convert(finding, args.source, rows)))
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except RecursionError:
        print("error: the input is nested too deeply", file=sys.stderr)
        return 1

    out = sys.stdout
    if args.json:
        partials = [partial for _, _, (partial, _, _, _) in results]
        json.dump(partials[0] if len(partials) == 1 else partials, out, indent=2, ensure_ascii=False)
        out.write("\n")
        return 0
    for number, (position, finding, (_, applied, not_computed, conflicts)) in enumerate(results):
        if len(results) > 1 or args.index is not None:
            if number:
                out.write("\n")
            out.write(f"=== Finding {position}: {finding_id(finding)} ===\n")
        print_trace(applied, not_computed, conflicts, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
