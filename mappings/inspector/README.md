# Amazon Inspector mappings

[`inspector-to-ocsf.csv`](inspector-to-ocsf.csv) maps fields of the Amazon Inspector finding JSON to
OCSF fields. Package and code vulnerability findings become an OCSF **Vulnerability Finding**
(`class_uid` 2002). Network reachability findings become an OCSF **Detection Finding** (`class_uid` 2004).
See the [top-level README](../../README.md#how-to-read-the-mappings) for the columns and the path
notation shared by all sources.

| | |
| --- | --- |
| OCSF version | 1.9.0 |
| OCSF classes | Vulnerability Finding (`class_uid` 2002), Detection Finding (`class_uid` 2004), both `category_uid` 2 |
| OCSF profiles | `cloud`, `datetime`, `aws/cloud_resources` |
| AWS extension | [`aws`](https://github.com/ocsf/aws) (uid 998), version 1.2.0 |
| Source column | `inspector_field` |

## Field paths

- Inspector field paths follow the Inspector finding JSON, as returned by `ListFindings` and
  delivered to Amazon EventBridge, using dot notation from the root of the finding. For example,
  `packageVulnerabilityDetails.vulnerabilityId`.
- Only `resources[0]` of the Inspector finding is converted.
- Every `timestamp_t` field is also emitted as a `_dt` string field (for example `time_dt`), as the
  `datetime` profile defines.

## Which rows apply

- `Package Vulnerability`, `Code Vulnerability` and `Network Reachability` rows apply when `type` is
  `PACKAGE_VULNERABILITY`, `CODE_VULNERABILITY` or `NETWORK_REACHABILITY` respectively.
- Resource rows apply when `resources[0].details` holds the matching object:

  | Area | `resources[0].details` object |
  | --- | --- |
  | `EC2 Instance` | `awsEc2Instance` |
  | `Other VM` | `vm`, when there is no `awsEc2Instance` |
  | `ECR Container Image` | `awsEcrContainerImage` |
  | `Other Container Image` | `image`, when there is no `awsEcrContainerImage` |
  | `Lambda Function` | `awsLambdaFunction` |
  | `Other Serverless Function` | `serverlessFunction`, when there is no `awsLambdaFunction` |
  | `Other Resource Types` | none of the objects above |

  Rows for container images, functions and other resource types apply to package
  and code vulnerability findings only.
- Rows in the other areas apply to every finding.

The sample script evaluates these conditions.

## AWS extension attributes

Some OCSF fields used here are defined by the [AWS extension to OCSF](https://github.com/ocsf/aws)
(version 1.2.0), not by the core schema:

- `resources[].cloud_function`
- `resources[].device`
- `resources[].image`
- `resources[].ip_addresses`
- `resources[].subnet_info`
- `resources[].vpc_uid`
- `vulnerabilities[].cve.cvss[].adjusted_score`
- `vulnerabilities[].cve.cvss[].adjusted_vector_string`
- `vulnerabilities[].cve.cvss[].adjusted_metric_list`
