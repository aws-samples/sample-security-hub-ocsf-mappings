# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for sample/convert.py. Run with: python3 -m unittest discover -s sample -v"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import convert  # noqa: E402

FINDINGS = HERE / "findings"
GUARDDUTY_EC2 = FINDINGS / "guardduty" / "ec2-network-connection.json"
GUARDDUTY_IAM = FINDINGS / "guardduty" / "iam-api-call.json"
CSPM_S3 = FINDINGS / "security-hub-cspm" / "s3-control-failed.json"
INSPECTOR_PACKAGE = FINDINGS / "inspector" / "ec2-package-vulnerability.json"


def run(*args):
    """Run convert.main and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = convert.main(list(args))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class TempFiles(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def write(self, name, content):
        path = Path(self._tmp.name) / name
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(content)
        return str(path)


class SampleFindings(unittest.TestCase):
    def test_every_sample_converts(self):
        for source in convert.SOURCES:
            for path in sorted((FINDINGS / source).glob("*.json")):
                with self.subTest(source=source, file=path.name):
                    code, out, err = run("--source", source, str(path))
                    self.assertEqual(code, 0, err)
                    self.assertIn("Applied mappings", out)
                    code, out, err = run("--source", source, "--json", str(path))
                    self.assertEqual(code, 0, err)
                    self.assertIsInstance(json.loads(out), dict)


class Transforms(unittest.TestCase):
    def test_direct_rows_are_copied(self):
        code, out, _ = run("--source", "guardduty", "--json", str(GUARDDUTY_EC2))
        self.assertEqual(code, 0)
        ocsf = json.loads(out)
        self.assertEqual(ocsf["cloud"]["account"]["uid"], "123456789012")
        self.assertEqual(ocsf["finding_info"]["title"], load(GUARDDUTY_EC2)["title"])

    def test_converted_rows_are_listed_not_computed(self):
        code, out, _ = run("--source", "guardduty", str(GUARDDUTY_EC2))
        self.assertEqual(code, 0)
        not_computed = out.split("Not computed", 1)[1]
        self.assertIn("severity -> severity_id (converted)", not_computed)
        code, out, _ = run("--source", "guardduty", "--json", str(GUARDDUTY_EC2))
        self.assertNotIn("severity_id", json.loads(out))


class Paths(unittest.TestCase):
    def test_array_elements(self):
        finding = load(GUARDDUTY_EC2)
        values = convert.resolve(finding, "guardduty", "resource.instanceDetails.networkInterfaces[].securityGroups[].groupId")
        self.assertEqual([v for _, v, _ in values], ["sg-0123456789abcdef0"])
        self.assertEqual(values[0][0], (0, 0))

    def test_first_element(self):
        finding = load(INSPECTOR_PACKAGE)
        values = convert.resolve(finding, "inspector", "resources[0].id")
        self.assertEqual([v for _, v, _ in values], ["i-0123456789abcdef0"])
        self.assertEqual(values[0][0], ())

    def test_map_keys(self):
        finding = load(INSPECTOR_PACKAGE)
        values = convert.resolve(finding, "inspector", "resources[0].tags.*")
        self.assertEqual([(v, k) for _, v, k in values], [("example-instance", "Name")])

    def test_guardduty_additional_info_value_is_decoded(self):
        finding = load(GUARDDUTY_IAM)
        values = convert.resolve(finding, "guardduty", "service.additionalInfo.value.sample")
        self.assertEqual([v for _, v, _ in values], [True])

    def test_guardduty_additional_info_value_that_is_not_json(self):
        finding = load(GUARDDUTY_IAM)
        finding["service"]["additionalInfo"]["value"] = "{not json"
        self.assertEqual(convert.resolve(finding, "guardduty", "service.additionalInfo.value.sample"), [])

    def test_cspm_product_fields_key(self):
        finding = load(CSPM_S3)
        values = convert.resolve(finding, "security-hub-cspm", "ProductFields.RelatedAWSResources:0/type")
        self.assertEqual([v for _, v, _ in values], ["AWS::Config::ConfigRule"])


class InputShapes(TempFiles):
    def test_findings_wrapper(self):
        path = self.write("wrapped.json", {"Findings": [load(GUARDDUTY_EC2), load(GUARDDUTY_IAM)]})
        code, out, _ = run("--source", "guardduty", path)
        self.assertEqual(code, 0)
        self.assertIn("=== Finding 0: a1b2c3d4e5f60718293a4b5c6d7e8f90 ===", out)
        self.assertIn("=== Finding 1: b2c3d4e5f60718293a4b5c6d7e8f90a1 ===", out)

    def test_lower_case_findings_wrapper(self):
        path = self.write("wrapped.json", {"findings": [load(INSPECTOR_PACKAGE)]})
        code, out, _ = run("--source", "inspector", "--json", path)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["finding_info"]["uid"], load(INSPECTOR_PACKAGE)["findingArn"])

    def test_eventbridge_event(self):
        event = {
            "version": "0",
            "id": "01234567-89ab-cdef-0123-456789abcdef",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "123456789012",
            "region": "us-east-1",
            "detail": load(GUARDDUTY_EC2),
        }
        path = self.write("event.json", event)
        code, out, _ = run("--source", "guardduty", "--json", path)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["finding_info"]["uid_alt"], load(GUARDDUTY_EC2)["id"])

    def test_index(self):
        path = self.write("wrapped.json", {"Findings": [load(GUARDDUTY_EC2), load(GUARDDUTY_IAM)]})
        code, out, _ = run("--source", "guardduty", "--index", "1", path)
        self.assertEqual(code, 0)
        self.assertIn("=== Finding 1:", out)
        self.assertNotIn("=== Finding 0:", out)
        code, _, err = run("--source", "guardduty", "--index", "5", path)
        self.assertEqual(code, 1)
        self.assertIn("out of range", err)

    def test_upper_case_keys_match_lower_case_keys(self):
        def upper(node):
            if isinstance(node, dict):
                return {(k[:1].upper() + k[1:]): upper(v) for k, v in node.items()}
            if isinstance(node, list):
                return [upper(v) for v in node]
            return node

        lower_path = str(GUARDDUTY_EC2)
        upper_path = self.write("upper.json", {"Findings": [upper(load(GUARDDUTY_EC2))]})
        _, lower_out, _ = run("--source", "guardduty", "--json", lower_path)
        code, upper_out, _ = run("--source", "guardduty", "--json", upper_path)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(lower_out), json.loads(upper_out))


class InvalidInput(TempFiles):
    def test_malformed_json(self):
        path = self.write("bad.json", '{"id": ')
        code, out, err = run("--source", "guardduty", path)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("not valid JSON", err)
        self.assertNotIn("Traceback", err)

    def test_file_over_size_limit_is_refused(self):
        path = self.write("big.json", b" " * (convert.MAX_INPUT_BYTES + 1))
        code, _, err = run("--source", "guardduty", path)
        self.assertEqual(code, 1)
        self.assertIn("refused", err)

    def test_deep_nesting(self):
        path = self.write("deep.json", "[" * 100000 + "]" * 100000)
        code, _, err = run("--source", "guardduty", path)
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", err)

    def test_missing_file(self):
        code, _, err = run("--source", "guardduty", os.path.join(self._tmp.name, "missing.json"))
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err)

    def test_usage_error(self):
        code, _, _ = run("--source", "unknown", str(GUARDDUTY_EC2))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
