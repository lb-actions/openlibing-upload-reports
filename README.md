# openlibing-upload-reports

<!-- 简短的一句话介绍该 Action 的核心功能 -->

一个用于在 GitHub Actions 流水线中上传测试元数据与结果文件到 OpenLibing OBS 桶的 GitHub Actions 插件。

<!-- 放置 GitHub Marketplace / CI 专属的 Badges -->

[![CI Test](https://github.com/lb-actions/openlibing-upload-reports/actions/workflows/ci.yml/badge.svg)](https://github.com/lb-actions/openlibing-upload-reports/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 核心特性 (Features)

- **OIDC 联邦认证**：通过工作流 OIDC ID Token 换取华为云 STS 临时凭证，使用 V11-HMAC-SHA256 签名上传请求，无需在仓库中存储 AK/SK 或 appcode。
- **双模式上传**：支持流水线模式（自动解析 workflow/job ID）与标签模式（自定义归档路径），适配不同归档场景。
- **路径安全校验**：对 `files`、`label`、`archive-path` 进行路径穿越与字符白名单校验，限制绝对路径仅允许 `/home`、`/tmp` 前缀。
- **多文件批量上传**：支持空格分隔的多文件批量上传，自动推断 MIME 类型并构造 `multipart/form-data` 请求体。
- **GitHub 原生**：运行于 [GitHub Actions](https://docs.github.com/en/actions)，使用 `GITHUB_*` 环境变量与 `actions/github-context`，运行时为 `node24`。

## 快速上手 (Quick Start)

在你的项目的 `.github/workflows/` 目录下创建一个 `.yml` 文件，并添加以下配置。使用本插件前必须先 `actions/checkout` 拉取代码。

### 最小可运行示例（流水线模式）

流水线模式通过 `GITHUB_RUN_ID` 与 GitHub API 自动解析 workflow ID 与 job ID，需传入 `github-token`：

```yaml
name: Upload Reports

on:
  push:
    branches:
      - main

permissions:
  id-token: write
  contents: read

jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      # Step 1: 必须先拉取你的代码仓库
      - name: Checkout code
        uses: actions/checkout@v4

      # Step 2: 使用本 Action 上传测试元数据
      - name: Upload metadata to OpenLibing
        uses: lb-actions/openlibing-upload-reports@v1
        with:
          files: metadata.xml results.xml
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 典型场景示例（标签模式）

标签模式不依赖流水线上下文，使用自定义 `label` 与 `archive-path` 归档，归档路径为 `/{label}/{archive-path}/{filename}`：

```yaml
name: Upload Reports (Label Mode)

on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Upload to OpenLibing (label mode)
        uses: lb-actions/openlibing-upload-reports@v1
        with:
          files: report.xml
          label: performance
          archive-path: 2026-09/run1
```

## 输入参数 (Inputs)

| 参数名称         | 是否必填 | 默认值 | 描述说明                                                                                                                                                          |
| :--------------- | :------: | :----- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `files`          | **是**   | 无     | 待上传文件路径，空格分隔的字符串。示例：`"metadata.xml results.xml"`。仅允许相对路径或 `/home`、`/tmp` 前缀的绝对路径，禁止包含 `..`。                            |
| `github-token`   |    否    | 无     | GitHub API Token，流水线模式下通过 GitHub API 解析 workflow ID 与 job ID。**建议传入 `${{ secrets.GITHUB_TOKEN }}`**：未提供时将以匿名方式调用 GitHub API，受 60 次/小时/IP 的速率限制，而 GitHub Actions runner 共享出口 IP 极易触发限流返回 403 导致流程失败；私有仓库必须传入。 |
| `label`          |    否    | 无     | 归档路径标签（如 `"performance"`、`"precision"`、`"simulation"`）。仅允许字母、数字、下划线、连字符、点，长度上限 256。提供时进入标签模式。                      |
| `archive-path`   |    否    | 无     | 自定义归档子路径，必须与 `label` 同时使用。仅允许字母、数字、斜杠、连字符、下划线、点、空格，长度上限 256，禁止包含 `..`。                                          |

## 输出参数 (Outputs)

| 输出名称        | 类型      | 描述说明                                                            |
| :-------------- | :-------- | :------------------------------------------------------------------ |
| `success`       | `boolean` | 上传是否成功（HTTP 状态码为 2xx 时为 `true`，否则为 `false`）。    |
| `status-code`   | `number`  | 上传响应的 HTTP 状态码；插件异常时为 `0`。                          |
| `response-text` | `string`  | 上传响应体（JSON 字符串化后）；插件异常时为错误消息文本。           |

### 如何使用输出参数示例

调用插件时指定 `id`，后续 Step 通过 `${{ steps.<step-id>.outputs.<output-name> }}` 引用：

```yaml
- name: Upload metadata to OpenLibing
  id: upload # 注意：这里必须指定 id
  uses: lb-actions/openlibing-upload-reports@v1
  with:
    files: metadata.xml results.xml
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Check upload result
  run: |
    echo "success: ${{ steps.upload.outputs.success }}"
    echo "status-code: ${{ steps.upload.outputs.status-code }}"
    echo "response: ${{ steps.upload.outputs.response-text }}"
```

## 权限要求 (Permissions)

本插件依赖 OIDC 联邦认证换取华为云 STS 临时凭证，调用工作流**必须**声明 `id-token: write`，否则无法申请 OIDC ID Token：

```yaml
permissions:
  contents: read # 读取仓库内容
  id-token: write # 必须声明此权限，否则无法申请 GitHub OIDC ID Token
```

IAM 侧前置配置（在华为云控制台一次性配置）：

- 注册 `GitHubActions` OIDC 提供商（issuer `https://token.actions.githubusercontent.com`，client ID `huawei-cloud-service`）。
- 创建信任委托（如 `github-actions`），信任策略约束 `oidc:iss` / `oidc:aud` / `oidc:sub`。其中 `oidc:sub` 形如 `repo:<owner>/<repo>`，用于限定允许换证的仓库范围。
- **仓库白名单**：委托信任策略通过 `oidc:sub` 的 `repo:` 前缀匹配来约束允许使用本委托的仓库。当前已在华为 IAM 侧纳入白名单的组织为 `sgl-project` 与 `vllm-project`，这两个组织下的仓库可直接使用；其余仓库需先在华为 IAM 委托信任策略中追加 `oidc:sub` 匹配规则后方可使用。如需新增白名单组织或仓库，请[提交 Issue](https://github.com/lb-actions/openlibing-upload-reports/issues) 或联系组织相关开发者。
- APIG 端点 `/openlibing-sync/sync/testcase/metadata/upload-iam` 配置为 **IAM 认证**。

## 贡献与本地调试 (Contributing & Debugging)

如果你想本地修改或调试这个 Action：

1. 克隆仓库并安装依赖：`npm install`
2. 打包生成分发文件：`npm run build`（执行 `tsc` 编译后用 `ncc` 打包 `dist/index.js` 并生成 `licenses.txt`）
3. 提交 PR 前请确保通过本地类型检查：`npx tsc --noEmit`
4. 提交 PR 前请在真实 GitHub Actions 流水线上验证以下能力：
   - [ ] 在 `.github/workflows/` 下手动触发一次最小流水线
   - [ ] 确认 `id-token: write` 权限可正常换证（OIDC 联邦登录成功）
   - [ ] 确认 `GITHUB_RUN_ID` / `GITHUB_REPOSITORY` 环境变量读取正确（流水线模式）
   - [ ] 确认 `permissions: actions: read` 可正常调用 GitHub API 解析 workflow/job ID

## 开源协议 (License)

[MIT](LICENSE) © openlibing
