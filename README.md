# AWS Security Hub OCSF mappings for Amazon GuardDuty, AWS Security Hub CSPM, and Amazon Inspector findings

AWS Security Hub receives findings from Amazon GuardDuty, AWS Security Hub CSPM and Amazon
Inspector and presents them in the [Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io/).
This repository documents, field by field, which field of each service's finding becomes which
field of the OCSF finding. It is meant for security engineers who read, query or forward these
OCSF findings and want to trace a value back to the field it came from. A small sample script
shows the mappings applied to example findings.

> **Notice:** This is sample content provided for reference. It describes how findings are mapped
> to OCSF as of the versions listed below. The OCSF findings that AWS Security Hub produces are the
> authoritative source. These mappings may not reflect later changes, and this repository is not a
> supported AWS product.

## Versions

| Source service | Source format | OCSF version | OCSF class (`class_uid`) | OCSF profiles | AWS extension | Mappings as of |
| --- | --- | --- | --- | --- | --- | --- |
| Amazon GuardDuty | GuardDuty finding JSON | 1.8.0 | Detection Finding (2004) | `cloud`, `datetime`; `container`, `osint`, `aws/cloud_resources` depending on the finding | `aws` 1.1.0 | 2026-11-06 |
| AWS Security Hub CSPM | AWS Security Finding Format (ASFF) | 1.8.0 | Compliance Finding (2003) | `cloud`, `datetime`, `aws/cloud_resources` | `aws` 1.1.0 | 2026-11-06 |
| Amazon Inspector | Inspector finding JSON | 1.9.0 | Vulnerability Finding (2002), Detection Finding (2004) | `cloud`, `datetime`, `aws/cloud_resources` | `aws` 1.2.0 | 2026-11-06 |

The AWS extension to OCSF is published at [github.com/ocsf/aws](https://github.com/ocsf/aws).

## Repository contents

| Path | Contents |
| --- | --- |
| [`mappings/guardduty/`](mappings/guardduty/) | GuardDuty mappings: [`guardduty-to-ocsf.csv`](mappings/guardduty/guardduty-to-ocsf.csv), the same data as JSON and Markdown, and a [README](mappings/guardduty/README.md) with GuardDuty-specific rules. |
| [`mappings/security-hub-cspm/`](mappings/security-hub-cspm/) | Security Hub CSPM mappings: [`asff-to-ocsf.csv`](mappings/security-hub-cspm/asff-to-ocsf.csv), JSON, Markdown and a [README](mappings/security-hub-cspm/README.md). |
| [`mappings/inspector/`](mappings/inspector/) | Inspector mappings: [`inspector-to-ocsf.csv`](mappings/inspector/inspector-to-ocsf.csv), JSON, Markdown and a [README](mappings/inspector/README.md). |
| [`sample/convert.py`](sample/convert.py) | Sample script that applies the mappings to a finding. |
| [`sample/findings/`](sample/findings/) | Example findings with placeholder values, two per source. |
| [`sample/test_convert.py`](sample/test_convert.py) | Tests for the sample script. |
| [`tools/build.py`](tools/build.py) | Validates the CSV files and regenerates the JSON and Markdown files. |

## How to read the mappings

Each source has one CSV file. Its JSON and `MAPPINGS.md` files hold the same rows and are
generated from it.

| Column | Meaning |
| --- | --- |
| `area` | The part of the finding the row belongs to, for example `EC2 Instance`, `Compliance` or `Package Vulnerability`. |
| `guardduty_field`, `asff_field`, `inspector_field` | The field of the source finding that the value comes from. The column name tells you which format the path belongs to. |
| `ocsf_field` | The OCSF field that receives the value. |
| `ocsf_type` | The OCSF data type of `ocsf_field`. |
| `transform` | How the value gets from the source field to the OCSF field (see below). |

`transform` is one of:

- `direct`: the value is copied unchanged, apart from its data type. Timestamps are converted to
  epoch milliseconds (`timestamp_t`), and numbers and strings are converted to the type in
  `ocsf_type`, for example an autonomous system number from a string to an integer.
- `converted`: the OCSF value is produced from the source value, for example a severity label that
  becomes a severity ID, or an ID taken from an ARN. The tables don't describe the conversion.

A source field can map to more than one OCSF field, and an OCSF field can be filled from different
source fields depending on the finding.

### Path notation

- Paths use dot notation from the root of the finding or the OCSF event. For example,
  `resource.instanceDetails.instanceId` or `resources[].uid`.
- `[]` marks an array. A row for `resources[].uid` applies to each element of `resources`.
- `[0]` and `[1]` mark the first and second element of an array only.
- `*` matches any key of a map. When the OCSF field ends in `.name`, it receives the map key;
  otherwise it receives the value.

### Source-specific rules

Each source has its own path rules and conditions for which rows apply:

- [GuardDuty](mappings/guardduty/README.md)
- [Security Hub CSPM (ASFF)](mappings/security-hub-cspm/README.md)
- [Inspector](mappings/inspector/README.md)

## Try the sample

`sample/convert.py` reads a finding and prints every mapping row whose source field has a value:
the source path, the value, the OCSF path and the transform. Rows with transform `direct` are
copied into a partial OCSF finding, which `--json` prints instead of the trace.

### With the included examples

You need Python 3.8 or later and nothing else. The script makes no AWS calls, so you don't need an
AWS account or credentials.

```
python3 sample/convert.py --source guardduty sample/findings/guardduty/iam-api-call.json
python3 sample/convert.py --source security-hub-cspm sample/findings/security-hub-cspm/s3-control-failed.json
python3 sample/convert.py --source inspector sample/findings/inspector/ec2-package-vulnerability.json
```

Excerpt of the output of the first command:

```
Applied mappings (source path -> value -> OCSF path -> transform)
  accountId -> 123456789012 -> cloud.account.uid -> direct
  partition -> aws -> cloud.cloud_partition -> direct
  region -> us-east-1 -> cloud.region -> direct
  service.count -> 3 -> count -> direct
  updatedAt -> 2026-02-02T09:25:00.000Z -> time -> direct
  ...
Not computed (the source field has a value, but its conversion is not described in the tables)
  service.archived -> activity_id (converted)
  service.count -> activity_id (converted)
  service.archived -> activity_name (converted)
  ...
```

Add `--json` to print the partial OCSF finding. When a file holds several findings, add
`--index N` to process only finding `N` (counting from 0).

### With findings from your own account

The script also reads findings that you export with the AWS CLI: a single finding, a
`get-findings` or `list-findings` response, or an Amazon EventBridge event. The script itself makes
no AWS calls; you run the CLI commands.

```
# Amazon GuardDuty: generate the built-in sample findings, then export them
aws guardduty list-detectors
aws guardduty create-sample-findings --detector-id <detector-id>
aws guardduty list-findings --detector-id <detector-id> \
    --finding-criteria '{"Criterion":{"service.additionalInfo.sample":{"Eq":["true"]}}}'
aws guardduty get-findings --detector-id <detector-id> --finding-ids <id> [<id> ...] > guardduty-findings.json
python3 sample/convert.py --source guardduty guardduty-findings.json

# AWS Security Hub CSPM (ASFF) control findings
aws securityhub get-findings --max-items 5 \
    --filters '{"ProductName":[{"Value":"Security Hub","Comparison":"EQUALS"}]}' > cspm-findings.json
python3 sample/convert.py --source security-hub-cspm cspm-findings.json

# Amazon Inspector
aws inspector2 list-findings --max-items 5 > inspector-findings.json
python3 sample/convert.py --source inspector inspector-findings.json
```

The commands need these permissions: `guardduty:ListDetectors`, `guardduty:CreateSampleFindings`,
`guardduty:ListFindings`, `guardduty:GetFindings`, `securityhub:GetFindings` and
`inspector2:ListFindings`. All of them are read-only except `guardduty:CreateSampleFindings`,
which adds sample findings to your GuardDuty findings list. You can archive those findings
afterwards.

Exported findings contain details of your own account and resources. Don't share the files or the
script output publicly.

### What the sample does not do

- It does not compute `converted` rows. It lists them under "Not computed".
- It copies `direct` values without converting their data type, so timestamps in the partial
  finding stay as they are in the source finding.
- It evaluates only the row conditions that the source READMEs name. All other rows apply whenever
  their source field has a value.
- It does not produce complete OCSF findings and does not validate them against the OCSF schema.
  Fields that come from different resources, actions or evidence entries can end up in the same
  array element of the partial finding.

## Regenerating the generated files

After editing a CSV file, regenerate the JSON and Markdown files:

```
python3 tools/build.py
```

To validate the CSV files and the sample findings, and confirm the generated files are up to date
without writing them:

```
python3 tools/build.py --check
```

Add a source name, such as `guardduty`, to limit either command to one source.

## Running the tests

```
python3 -m unittest discover -s sample -v
```

## Feedback and contributions

Issues are welcome. If you find a mapping that doesn't match the OCSF findings in Security Hub,
open an issue with the source field and the OCSF field.

The mapping files describe how AWS Security Hub converts findings, so we don't accept pull
requests that change them. If a mapping doesn't match the OCSF findings you see in Security Hub,
open an issue with the source field, the OCSF field and what you observed. Pull requests that fix
the documentation or the sample script are welcome.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
