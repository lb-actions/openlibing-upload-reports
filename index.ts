import * as core from "@actions/core";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import * as mime from "mime-types";

const { callApig, configure } = require("@openlibing/huaweicloud-oidc-client") as {
  callApig: (
    method: string,
    url: string,
    headers?: Record<string, string>,
    body?: Buffer | string,
    opts?: { force?: boolean; region?: string }
  ) => Promise<{ status: number; headers: Record<string, string>; data: any }>;
  configure: (overrides?: Record<string, unknown>) => Record<string, unknown>;
};

// 本插件运行在 GitHub Actions，覆盖 SDK 默认的 GitCodeActions 提供商
configure({ oidcProviderName: "GitHubActions", agencyName: "github-actions" });

interface MultipartFile {
  filename: string;
  contentType: string;
  buffer: Buffer;
}

interface UploadConfig {
  workflowId?: string | null;
  pipelineRunId?: string | null;
  jobId?: string | null;
  label?: string;
  archivePath?: string;
}

interface UploadResult {
  status: number;
  data: any;
}

/**
 * Validate file path for security.
 * Prevents path traversal attacks and restricts absolute paths to allowed directories.
 */
function validateFilePath(filePath: string): string {
  if (!filePath || filePath.trim() === "") {
    throw new Error("File path cannot be empty");
  }

  const trimmedPath = filePath.trim();

  // Reject paths containing path traversal sequences
  if (trimmedPath.includes("..")) {
    throw new Error(`Path traversal not allowed: ${trimmedPath}`);
  }

  // Resolve path (works for both relative and absolute paths)
  const resolvedPath = path.resolve(trimmedPath);

  // For absolute paths, check against allowed directories whitelist
  if (path.isAbsolute(trimmedPath)) {
    // Security: Use explicit paths instead of process.cwd() to avoid exposing sensitive files
    // when running as root user (e.g., /root/.ssh/id_rsa)
    const ALLOWED_PREFIXES = ["/home", "/tmp"];

    const isAllowed = ALLOWED_PREFIXES.some((prefix) => {
      const normalizedPrefix = path.resolve(prefix);
      return resolvedPath.startsWith(normalizedPrefix);
    });

    if (!isAllowed) {
      throw new Error(
        `Absolute path must be within allowed directories: ${ALLOWED_PREFIXES.join(", ")}. ` +
          `Got: ${trimmedPath}`
      );
    }
  }

  return resolvedPath;
}

/**
 * Build a multipart/form-data body as a single Buffer with a fixed boundary.
 * V11 signing requires the complete body upfront (cannot sign streaming bodies),
 * so files are read into memory and concatenated with a boundary shared between
 * the body and the Content-Type header.
 */
function buildMultipartBody(
  fields: Record<string, string>,
  files: MultipartFile[],
  boundary: string
): Buffer {
  const eol = "\r\n";
  const parts: Buffer[] = [];

  for (const [name, value] of Object.entries(fields)) {
    parts.push(
      Buffer.from(
        `--${boundary}${eol}` +
          `Content-Disposition: form-data; name="${name}"${eol}${eol}` +
          `${value}${eol}`
      )
    );
  }

  for (const file of files) {
    parts.push(
      Buffer.from(
        `--${boundary}${eol}` +
          `Content-Disposition: form-data; name="files"; filename="${file.filename}"${eol}` +
          `Content-Type: ${file.contentType}${eol}${eol}`
      )
    );
    parts.push(file.buffer);
    parts.push(Buffer.from(eol));
  }

  parts.push(Buffer.from(`--${boundary}--${eol}`));
  return Buffer.concat(parts);
}

/**
 * Validate label parameter for security.
 * Only allows alphanumeric characters, underscore, hyphen, and dot.
 */
function validateLabel(label: string): string {
  if (!label || label.trim() === "") {
    return "";
  }
  const trimmed = label.trim();
  // Allow alphanumeric, underscore, hyphen, and dot
  if (!/^[a-zA-Z0-9_.\-]+$/.test(trimmed)) {
    throw new Error(
      `label contains invalid characters. Only alphanumeric, underscore, hyphen and dot are allowed`
    );
  }
  if (trimmed.length > 256) {
    throw new Error("label exceeds maximum length of 256 characters");
  }
  return trimmed;
}

/**
 * Validate archive-path parameter for security.
 * Restricts to safe path characters (alphanumeric, slash, hyphen, underscore, dot).
 */
function validateArchivePath(archivePath: string): string {
  if (!archivePath || archivePath.trim() === "") {
    return "";
  }
  const trimmed = archivePath.trim();
  // Reject path traversal
  if (trimmed.includes("..")) {
    throw new Error('archive-path cannot contain ".." (path traversal)');
  }
  // Allow safe path characters: alphanumeric, slash, hyphen, underscore, dot
  if (!/^[a-zA-Z0-9/_\-.\s]+$/.test(trimmed)) {
    throw new Error(
      "archive-path contains invalid characters. Only alphanumeric, slash, hyphen, underscore, dot and space are allowed"
    );
  }
  if (trimmed.length > 256) {
    throw new Error("archive-path exceeds maximum length of 256 characters");
  }
  return trimmed;
}

/**
 * Fetch job ID from GitHub API.
 * Returns the first job ID from the current workflow run.
 */
async function fetchJobIdFromGitHub(githubToken: string): Promise<string> {
  const githubRunId = process.env.GITHUB_RUN_ID;
  const githubRepository = process.env.GITHUB_REPOSITORY;

  if (!githubRunId || !githubRepository) {
    throw new Error("GITHUB_RUN_ID or GITHUB_REPOSITORY environment variable not set");
  }

  const [owner, repo] = githubRepository.split("/");
  const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${githubRunId}/jobs`;

  console.log(`Fetching job ID from GitHub API: ${url}`);

  const response = await axios.get(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${githubToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Node.js-axios/1.6.0",
    },
  });

  const jobs = response.data.jobs;
  if (!jobs || jobs.length === 0) {
    throw new Error("No jobs found in the current workflow run");
  }

  const jobId = jobs[0].id;
  console.log(`Fetched job ID: ${jobId}`);
  return String(jobId);
}

/**
 * Fetch workflow ID from GitHub API.
 * Returns the workflow_id from the current workflow run.
 */
async function fetchWorkflowIdFromGitHub(githubToken: string): Promise<string> {
  const githubRunId = process.env.GITHUB_RUN_ID;
  const githubRepository = process.env.GITHUB_REPOSITORY;

  if (!githubRunId || !githubRepository) {
    throw new Error("GITHUB_RUN_ID or GITHUB_REPOSITORY environment variable not set");
  }

  const [owner, repo] = githubRepository.split("/");
  const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${githubRunId}`;

  console.log(`Fetching workflow ID from GitHub API: ${url}`);

  const response = await axios.get(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${githubToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "Node.js-axios/1.6.0",
    },
  });

  const workflowId = response.data.workflow_id;
  if (!workflowId) {
    throw new Error("workflow_id not found in the response");
  }

  console.log(`Fetched workflow ID: ${workflowId}`);
  return String(workflowId);
}

/**
 * Upload files to OpenLibing OBS bucket.
 * Uses OIDC-federated credentials via the SDK's callApig (auto V11-HMAC-SHA256
 * signing + X-Security-Token); the multipart body is built as a single Buffer
 * so V11 payload hashing can run over the complete body.
 */
async function uploadFiles(
  files: string[],
  uploadConfig: UploadConfig
): Promise<UploadResult> {
  const url =
    "https://apig.openlibing.com/openlibing-sync/sync/testcase/metadata/upload-iam";
  const workflowId = uploadConfig.workflowId || "";
  const pipelineRunId = uploadConfig.pipelineRunId || "";
  const jobId = uploadConfig.jobId || "";
  const label = uploadConfig.label || "";
  const archivePath = uploadConfig.archivePath || "";

  console.log(`Uploading ${files.length} files to OpenLibing...`);
  console.log(`URL: ${url}`);

  const boundary = "----OpenLibingUpload" + Math.random().toString(16).slice(2);
  const fields: Record<string, string> = {};
  if (workflowId) {
    fields.pipelineId = workflowId;
  }
  if (pipelineRunId) {
    fields.pipelineRunId = pipelineRunId;
  }
  if (jobId) {
    fields.jobId = jobId;
  }

  const archiveConfig: Record<string, string> = {};
  if (label) {
    archiveConfig.label = label;
  }
  if (archivePath) {
    archiveConfig.archivePath = archivePath;
  }
  if (Object.keys(archiveConfig).length > 0) {
    fields.archiveConfig = JSON.stringify(archiveConfig);
  }

  const fileParts: MultipartFile[] = [];
  const validFiles: string[] = [];
  for (const filePath of files) {
    // Security: Validate file path to prevent arbitrary file read
    const validatedPath = validateFilePath(filePath);
    if (!fs.existsSync(validatedPath)) {
      console.log(`Warning: File not found, skipping: ${filePath}`);
      continue;
    }
    const fileName = path.basename(validatedPath);
    const mimeType = mime.lookup(validatedPath) || "application/octet-stream";
    fileParts.push({
      filename: fileName,
      contentType: mimeType,
      buffer: fs.readFileSync(validatedPath),
    });
    validFiles.push(fileName);
  }

  if (validFiles.length === 0) {
    throw new Error("No valid files to upload");
  }
  console.log(`Uploading ${validFiles.length} files: ${validFiles.join(", ")}`);

  const body = buildMultipartBody(fields, fileParts, boundary);
  const headers = {
    "Content-Type": `multipart/form-data; boundary=${boundary}`,
  };

  const response = await callApig("POST", url, headers, body);

  console.log(`Upload response status: ${response.status}`);
  console.log(`Upload response text: ${JSON.stringify(response.data)}`);

  return {
    status: response.status,
    data: response.data,
  };
}

async function run(): Promise<void> {
  try {
    console.log("=".repeat(60));
    console.log("Starting OpenLibing metadata upload...");
    console.log("=".repeat(60));

    // Step 1: Get input parameters
    core.startGroup("Step 1: Get input parameters");
    const filesInput = core.getInput("files", { required: true });
    const labelRaw = core.getInput("label", { required: false });
    const archivePathRaw = core.getInput("archive-path", { required: false });

    // Security: Validate label and archive-path parameters
    const label = validateLabel(labelRaw);
    const archivePath = validateArchivePath(archivePathRaw);

    // Determine mode: label mode or pipeline mode
    const isLabelMode = Boolean(label);

    let workflowId: string | null;
    let pipelineRunId: string | null;
    let jobId: string | null;
    if (isLabelMode) {
      // Label mode: ignore pipeline params
      workflowId = null;
      pipelineRunId = null;
      jobId = null;
    } else {
      // Pipeline mode: use GITHUB_RUN_ID and fetch IDs from API
      const githubToken = core.getInput("github-token", { required: true });
      pipelineRunId = process.env.GITHUB_RUN_ID || null;
      if (!pipelineRunId) {
        throw new Error("GITHUB_RUN_ID environment variable not set");
      }
      workflowId = await fetchWorkflowIdFromGitHub(githubToken);
      jobId = await fetchJobIdFromGitHub(githubToken);
    }

    const files = filesInput.split(/\s+/).filter((f) => f.length > 0);

    console.log("Input parameters loaded:");
    console.log(`  - files: ${files.join(", ")}`);
    console.log(`  - workflow-id: ${workflowId || "(not set)"}`);
    console.log(`  - pipeline-run-id: ${pipelineRunId || "(not set)"}`);
    console.log(`  - job-id: ${jobId || "(not set)"}`);
    console.log(`  - label: ${label || "(not set)"}`);
    console.log(`  - archive-path: ${archivePath || "(not set)"}`);
    core.endGroup();

    core.startGroup("Step 2: Validate parameters");
    try {
      const hasArchivePath = Boolean(archivePath);
      const hasLabel = Boolean(label);

      if (hasArchivePath && !hasLabel) {
        core.error("archive-path requires label");
        throw new Error("archive-path requires label");
      }

      if (!isLabelMode) {
        // Pipeline mode validation
        if (!workflowId || !pipelineRunId || !jobId) {
          core.error(
            "Pipeline mode requires workflow-id, pipeline-run-id and job-id"
          );
          throw new Error(
            "Pipeline mode requires workflow-id, pipeline-run-id and job-id"
          );
        }
      }
    } finally {
      core.endGroup();
    }

    // Step 3: Upload files
    core.startGroup("Step 3: Upload files");
    let uploadResult: UploadResult;
    try {
      uploadResult = await uploadFiles(files, {
        workflowId,
        pipelineRunId,
        jobId,
        label,
        archivePath,
      });
    } finally {
      core.endGroup();
    }

    // Step 4: Set outputs
    core.startGroup("Step 4: Set outputs");
    try {
      const success =
        uploadResult.status >= 200 && uploadResult.status < 300;
      console.log("Execution outputs:");
      if (success) {
        core.setOutput("success", "true");
        core.setOutput("status-code", String(uploadResult.status));
        core.setOutput("response-text", JSON.stringify(uploadResult.data));
        console.log("=".repeat(60));
        console.log("Metadata upload completed successfully");
        console.log("=".repeat(60));
      } else {
        core.setOutput("success", "false");
        core.setOutput("status-code", String(uploadResult.status));
        core.setOutput("response-text", JSON.stringify(uploadResult.data));
        core.error(`Upload failed with status ${uploadResult.status}`);
        core.setFailed(`Upload failed with status ${uploadResult.status}`);
      }
    } finally {
      core.endGroup();
    }
  } catch (error: any) {
    core.setOutput("success", "false");
    core.setOutput("status-code", "0");
    core.setOutput("response-text", error.message);
    core.error("=".repeat(60));
    core.error(`Metadata upload failed: ${error.message}`);
    core.error("=".repeat(60));
    if (error.stack) {
      core.error(`Stack trace:\n${error.stack}`);
    }
    core.setFailed(error.message);
  }
}

run();