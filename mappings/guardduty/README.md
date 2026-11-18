# Amazon GuardDuty mappings

[`guardduty-to-ocsf.csv`](guardduty-to-ocsf.csv) maps fields of the GuardDuty finding JSON to
OCSF **Detection Finding** (`class_uid` 2004) fields. See the [top-level README](../../README.md#how-to-read-the-mappings)
for the columns and the path notation shared by all sources.

| | |
| --- | --- |
| OCSF version | 1.8.0 |
| OCSF class | Detection Finding (`class_uid` 2004, `category_uid` 2) |
| OCSF profiles | `cloud`, `datetime`, and, depending on the finding, `container`, `osint`, `aws/cloud_resources` |
| AWS extension | [`aws`](https://github.com/ocsf/aws) (uid 998), version 1.1.0 |
| Source column | `guardduty_field` |

## Field paths

- GuardDuty field paths follow the GuardDuty finding JSON, as returned by `GetFindings` and
  delivered to Amazon EventBridge, using dot notation from the root of the finding. For example,
  `resource.instanceDetails.instanceId`.
- `service.additionalInfo.value` is a JSON-encoded string. Paths that continue after it, for
  example `service.additionalInfo.value.sample`, refer to keys of the decoded JSON object.

## Which rows apply

Rows apply when their GuardDuty field has a value. Rows for a resource or action type read fields
that only that type has, for example `resource.instanceDetails.*` for EC2 instances or
`service.action.awsApiCallAction.*` for API calls.

## AWS extension attributes

Some OCSF fields used here are defined by the [AWS extension to OCSF](https://github.com/ocsf/aws)
(version 1.1.0), not by the core schema:

- `guardrail_evaluation_result`
- `resources[].cloud_function`
- `resources[].database`
- `resources[].databucket`
- `resources[].device`
- `resources[].storage_device`
- `resources[].user`
- `resources[].vpc_uid`

The `resources[]` fields above belong to the `aws/cloud_resources` profile.
