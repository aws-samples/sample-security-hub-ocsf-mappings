# AWS Security Hub CSPM (ASFF) mappings

[`asff-to-ocsf.csv`](asff-to-ocsf.csv) maps fields of AWS Security Hub CSPM control findings in the
[AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
to OCSF **Compliance Finding** (`class_uid` 2003) fields. See the
[top-level README](../../README.md#how-to-read-the-mappings) for the columns and the path notation
shared by all sources.

| | |
| --- | --- |
| OCSF version | 1.8.0 |
| OCSF class | Compliance Finding (`class_uid` 2003, `category_uid` 2) |
| OCSF profiles | `cloud`, `datetime`, `aws/cloud_resources` |
| AWS extension | [`aws`](https://github.com/ocsf/aws) (uid 998), version 1.1.0 |
| Source column | `asff_field` |

## Field paths

- ASFF field paths follow the
  [`AwsSecurityFinding`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFinding.html)
  JSON, using dot notation from the root of the finding. For example, `Compliance.SecurityControlId`.
- `ProductFields` is a string map. A path such as `ProductFields.RelatedAWSResources:0/name` refers to
  the map key `RelatedAWSResources:0/name`.
- Every `timestamp_t` field is also emitted as a `_dt` string field (for example `time_dt`), as the
  `datetime` profile defines.

## Which rows apply

- Rows in the `Resource` area apply to every resource.
- `AWS Resource` rows apply when `Resources[].Provider` is not `Azure`.
- `Azure Resource` rows apply when `Resources[].Provider` is `Azure`.

The sample script evaluates these two conditions.
