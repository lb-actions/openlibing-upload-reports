# openlibing-upload-reports

Upload test metadata and result files to the OpenLibing OBS bucket via the OpenLibing APIG endpoint.

Authentication uses **OIDC federated identity** (no AK/SK or appcode stored in the repo): the workflow's OIDC ID Token is exchanged for Huawei Cloud STS temporary credentials, which sign the upload request via V11-HMAC-SHA256. Powered by `@openlibing/huaweicloud-oidc-client`.

## Required workflow permissions

The calling workflow **must** declare `id-token: write`, otherwise the action cannot request an OIDC ID Token:

```yaml
permissions:
  contents: read
  id-token: write
```

IAM prerequisites (configure once on the Huawei Cloud side):

- Register a `GitHubActions` OIDC provider (issuer `https://token.actions.githubusercontent.com`, client ID `huawei-cloud-service`).
- Create a trust agency (e.g. `gitcode-actions`) with a trust policy constraining `oidc:iss` / `oidc:aud` / `oidc:sub`.
- Configure the APIG endpoint `/openlibing-sync/sync/testcase/metadata/upload` for **IAM authentication**.

## Inputs

| Input | Description | Required |
|-------|-------------|----------|
| `files` | File paths to upload (space-separated). Example: `"metadata.xml results.xml"` | yes |
| `github-token` | GitHub token for API authentication. Required in pipeline mode (no `label`). | no |
| `label` | Label for archive path (e.g. `"performance"`). Required if not using pipeline params. | no |
| `archive-path` | Custom archive path. Must be used with `label`. | no |

## Outputs

| Output | Description |
|--------|-------------|
| `success` | Upload success status (`true`/`false`) |
| `status-code` | HTTP response status code |
| `response-text` | HTTP response text |

## Usage

Pipeline mode (uses `GITHUB_RUN_ID` + GitHub API to resolve workflow/job IDs):

```yaml
- name: Upload metadata to OpenLibing
  uses: lb-actions/openlibing-upload-reports@v1
  with:
    files: metadata.xml results.xml
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

Label mode:

```yaml
- name: Upload to OpenLibing (label mode)
  uses: lb-actions/openlibing-upload-reports@v1
  with:
    files: report.xml
    label: performance
    archive-path: 2026-09/run1
```
