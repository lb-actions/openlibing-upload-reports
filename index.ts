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
async function fetchJobIdFromGitHub(githubToken?: string): Promise<string> {
  const githubRunId = process.env.GITHUB_RUN_ID;
  const githubRepository = process.env.GITHUB_REPOSITORY;

  if (!githubRunId || !githubRepository) {
    throw new Error("GITHUB_RUN_ID or GITHUB_REPOSITORY environment variable not set");
  }

  const [owner, repo] = githubRepository.split("/");
  const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${githubRunId}/jobs`;

  console.log(`Fetching job ID from GitHub API: ${url}`);

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Node.js-axios/1.6.0",
  };
  if (githubToken) {
    headers.Authorization = `Bearer ${githubToken}`;
  } else {
    console.log(
      "github-token not provided, calling GitHub API unauthenticated " +
        "(public repos only, 60 req/hour per IP)"
    );
  }

  let response;
  try {
    response = await axios.get(url, { headers });
  } catch (error: any) {
    const status = error?.response?.status;
    const rateLimitRemaining = error?.response?.headers?.["x-ratelimit-remaining"];
    const rateLimitLimit = error?.response?.headers?.["x-ratelimit-limit"];
    const body = error?.response?.data;
    console.error(
      `GitHub API request failed: status=${status}, ` +
        `x-ratelimit-remaining=${rateLimitRemaining}/${rateLimitLimit}, ` +
        `authenticated=${githubToken ? "yes" : "no"}`
    );
    console.error(`Response body: ${JSON.stringify(body)}`);
    throw new Error(
      `GitHub API request to ${url} failed with status ${status}: ` +
        `${JSON.stringify(body?.message || body)}`
    );
  }

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
async function fetchWorkflowIdFromGitHub(githubToken?: string): Promise<string> {
  const githubRunId = process.env.GITHUB_RUN_ID;
  const githubRepository = process.env.GITHUB_REPOSITORY;

  if (!githubRunId || !githubRepository) {
    throw new Error("GITHUB_RUN_ID or GITHUB_REPOSITORY environment variable not set");
  }

  const [owner, repo] = githubRepository.split("/");
  const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${githubRunId}`;

  console.log(`Fetching workflow ID from GitHub API: ${url}`);

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Node.js-axios/1.6.0",
  };
  if (githubToken) {
    headers.Authorization = `Bearer ${githubToken}`;
  } else {
    console.log(
      "github-token not provided, calling GitHub API unauthenticated " +
        "(public repos only, 60 req/hour per IP)"
    );
  }

  let response;
  try {
    response = await axios.get(url, { headers });
  } catch (error: any) {
    const status = error?.response?.status;
    const rateLimitRemaining = error?.response?.headers?.["x-ratelimit-remaining"];
    const rateLimitLimit = error?.response?.headers?.["x-ratelimit-limit"];
    const body = error?.response?.data;
    console.error(
      `GitHub API request failed: status=${status}, ` +
        `x-ratelimit-remaining=${rateLimitRemaining}/${rateLimitLimit}, ` +
        `authenticated=${githubToken ? "yes" : "no"}`
    );
    console.error(`Response body: ${JSON.stringify(body)}`);
    throw new Error(
      `GitHub API request to ${url} failed with status ${status}: ` +
        `${JSON.stringify(body?.message || body)}`
    );
  }

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
  // Fixed platform identifier sent alongside the files
  fields.platform = "github";
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

/** Maximum size for a merged XML file (12 MB, APIG body limit). */
const MAX_MERGE_SIZE = 12 * 1024 * 1024;

/**
 * Generate a random alphabetic suffix of the given length.
 */
function generateRandomSuffix(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

/**
 * Extract the root element name of an XML document.
 *
 * Skips the XML declaration, comments, DOCTYPE, and leading whitespace, then
 * reads the name of the first real element tag. Only the document's opening
 * structure is inspected — we never substring-match against arbitrary body
 * content, so a JUnit <testsuites> file that happens to contain "<metadata>"
 * text inside a test name or message is no longer misclassified.
 */
function getXmlRootElement(content: string): string | null {
  const startMatch = content.match(
    /^\s*(?:<\?xml[\s\S]*?\?>\s*)?(?:<!--[\s\S]*?-->\s*)*(?:<!DOCTYPE[\s\S]*?>\s*)*<([a-zA-Z_][\w.-]*)/
  );
  return startMatch ? startMatch[1] : null;
}

/**
 * Detect XML format by checking the root element name.
 * Returns "metadata" for <metadata> root, "testsuites" for <testsuites> root,
 * or "unknown" if neither is found.
 */
function detectXmlFormat(
  content: string
): "metadata" | "testsuites" | "unknown" {
  const root = getXmlRootElement(content);
  if (root === "metadata") {
    return "metadata";
  }
  if (root === "testsuites") {
    return "testsuites";
  }
  return "unknown";
}

/**
 * Merge multiple metadata-format XML files into a single file.
 * Combines all <testCase> nodes under one <metadata> root.
 * Header info (pipelineId, frameType, repoUrl, etc.) is taken from the first file.
 */
function mergeMetadataXmls(xmlFiles: string[], outputPath: string): void {
  const firstContent = fs.readFileSync(xmlFiles[0], "utf-8");

  // Extract header: from <metadata> opening tag to <testCases> opening tag (inclusive)
  const headerMatch = firstContent.match(/<metadata>[\s\S]*?<testCases>/);
  const header = headerMatch ? headerMatch[0] : "<metadata>\n  <testCases>";

  // Extract footer: from </testCases> to </metadata> (inclusive)
  const footerMatch = firstContent.match(/<\/testCases>[\s\S]*?<\/metadata>/);
  const footer = footerMatch ? footerMatch[0] : "</testCases>\n</metadata>";

  // Collect all <testCase> nodes from all files
  const allTestCases: string[] = [];
  for (const xmlFile of xmlFiles) {
    const content = fs.readFileSync(xmlFile, "utf-8");
    const regex = /<testCase>[\s\S]*?<\/testCase>/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      allTestCases.push(match[0]);
    }
  }

  const merged =
    "<?xml version='1.0' encoding='utf-8'?>\n" +
    header +
    "\n" +
    allTestCases.join("\n") +
    "\n" +
    footer +
    "\n";

  fs.writeFileSync(outputPath, merged, "utf-8");
}

/**
 * Merge multiple testsuite-format XML files into a single file.
 * Combines all <testsuite> nodes under one <testsuites> root.
 */
function mergeTestsuiteXmls(xmlFiles: string[], outputPath: string): void {
  const allTestsuites: string[] = [];
  for (const xmlFile of xmlFiles) {
    const content = fs.readFileSync(xmlFile, "utf-8");
    const regex = /<testsuite[\s\S]*?<\/testsuite>/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      allTestsuites.push(match[0]);
    }
  }

  const merged =
    "<?xml version='1.0' encoding='utf-8'?>\n" +
    '<testsuites name="merged">\n' +
    allTestsuites.join("\n") +
    "\n" +
    "</testsuites>\n";

  fs.writeFileSync(outputPath, merged, "utf-8");
}

async function run(): Promise<void> {
  try {
    console.log("=".repeat(60));
    console.log("Starting OpenLibing metadata upload...");
    console.log("=".repeat(60));

    // Step 1: Get input parameters
    core.startGroup("Step 1: Get input parameters");
    const filesInput = core.getInput("files", { required: false });
    const filesDirInput = core.getInput("files-dir", { required: false });
    const labelRaw = core.getInput("label", { required: false });
    const archivePathRaw = core.getInput("archive-path", { required: false });

    // Security: Validate label and archive-path parameters
    const label = validateLabel(labelRaw);
    const archivePath = validateArchivePath(archivePathRaw);

    // Fast-fail: archive-path requires label before any file processing
    if (Boolean(archivePath) && !label) {
      throw new Error("archive-path requires label");
    }

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
      // Pipeline mode: use GITHUB_RUN_ID as the run id; resolve workflow/job
      // IDs via GitHub API. When github-token is provided, authenticate the
      // request (higher rate limit, private repos). When not provided, call
      // the API unauthenticated (public repos only, 60 req/hour per IP).
      const githubToken = core.getInput("github-token", { required: false });
      pipelineRunId = process.env.GITHUB_RUN_ID || null;
      if (!pipelineRunId) {
        throw new Error("GITHUB_RUN_ID environment variable not set");
      }
      workflowId = await fetchWorkflowIdFromGitHub(githubToken || undefined);
      jobId = await fetchJobIdFromGitHub(githubToken || undefined);

      // Fast-fail: pipeline mode requires all three IDs before file processing
      if (!workflowId || !pipelineRunId || !jobId) {
        throw new Error(
          "Pipeline mode requires workflow-id, pipeline-run-id and job-id"
        );
      }
    }

    // --- Process files parameter: individual file list ---
    const individualFiles: string[] = [];
    if (filesInput) {
      individualFiles.push(
        ...filesInput.split(/\s+/).filter((f) => f.length > 0)
      );
    }

    // --- Process files-dir parameter: read XML, classify, merge ---
    const mergedFiles: string[] = [];
    if (filesDirInput) {
      const validatedDir = validateFilePath(filesDirInput);
      if (
        !fs.existsSync(validatedDir) ||
        !fs.statSync(validatedDir).isDirectory()
      ) {
        throw new Error(`files-dir is not a valid directory: ${filesDirInput}`);
      }

      // Read all .xml files in the directory (non-recursive)
      const xmlFiles = fs
        .readdirSync(validatedDir)
        .filter((f) => f.endsWith(".xml"))
        .filter((f) => fs.statSync(path.join(validatedDir, f)).isFile())
        .map((f) => path.join(validatedDir, f))
        // Exclude previously generated merge files to avoid re-processing
        .filter(
          (f) =>
            !path.basename(f).startsWith("metadata_merge_") &&
            !path.basename(f).startsWith("test_result_")
        );

      if (xmlFiles.length === 0) {
        throw new Error(`No XML files found in files-dir: ${filesDirInput}`);
      }

      // Classify by root element format
      const metadataXmls: string[] = [];
      const testsuiteXmls: string[] = [];

      for (const xmlFile of xmlFiles) {
        const content = fs.readFileSync(xmlFile, "utf-8");
        const format = detectXmlFormat(content);
        if (format === "metadata") {
          metadataXmls.push(xmlFile);
        } else if (format === "testsuites") {
          testsuiteXmls.push(xmlFile);
        } else {
          core.warning(`Unknown XML format, skipping: ${xmlFile}`);
        }
      }

      // Merge metadata-format XML files
      if (metadataXmls.length > 0) {
        const suffix = generateRandomSuffix(5);
        const mergedFileName = `metadata_merge_${suffix}.xml`;
        const mergedPath = path.join(validatedDir, mergedFileName);
        mergeMetadataXmls(metadataXmls, mergedPath);

        const mergedSize = fs.statSync(mergedPath).size;
        if (mergedSize > MAX_MERGE_SIZE) {
          throw new Error(
            `Merged metadata file exceeds 12MB limit: ${mergedSize} bytes`
          );
        }
        mergedFiles.push(mergedPath);
        console.log(
          `Merged ${metadataXmls.length} metadata XML files into ` +
            `${mergedFileName} (${mergedSize} bytes)`
        );
      }

      // Merge testsuite-format XML files
      if (testsuiteXmls.length > 0) {
        const suffix = generateRandomSuffix(5);
        const mergedFileName = `test_result_${suffix}.xml`;
        const mergedPath = path.join(validatedDir, mergedFileName);
        mergeTestsuiteXmls(testsuiteXmls, mergedPath);

        const mergedSize = fs.statSync(mergedPath).size;
        if (mergedSize > MAX_MERGE_SIZE) {
          throw new Error(
            `Merged testsuite file exceeds 12MB limit: ${mergedSize} bytes`
          );
        }
        mergedFiles.push(mergedPath);
        console.log(
          `Merged ${testsuiteXmls.length} testsuite XML files into ` +
            `${mergedFileName} (${mergedSize} bytes)`
        );
      }
    }

    // At least one upload source must be provided
    if (individualFiles.length === 0 && mergedFiles.length === 0) {
      throw new Error(
        "At least one of 'files' or 'files-dir' must be provided"
      );
    }

    console.log("Input parameters loaded:");
    console.log(`  - files (individual): ${individualFiles.join(", ") || "(none)"}`);
    console.log(`  - files-dir merged: ${mergedFiles.map((f) => path.basename(f)).join(", ") || "(none)"}`);
    console.log(`  - workflow-id: ${workflowId || "(not set)"}`);
    console.log(`  - pipeline-run-id: ${pipelineRunId || "(not set)"}`);
    console.log(`  - job-id: ${jobId || "(not set)"}`);
    console.log(`  - label: ${label || "(not set)"}`);
    console.log(`  - archive-path: ${archivePath || "(not set)"}`);
    core.endGroup();

    // Step 2: Upload files
    // files param: each file uploaded individually (1 API call per file)
    // files-dir merged: each merged file uploaded individually (1 API call per merged file)
    core.startGroup("Step 2: Upload files");
    const uploadResults: { file: string; result: UploadResult }[] = [];
    try {
      // Upload individual files from files param
      for (const file of individualFiles) {
        console.log(`Uploading individual file: ${file}`);
        const result = await uploadFiles([file], {
          workflowId,
          pipelineRunId,
          jobId,
          label,
          archivePath,
        });
        uploadResults.push({ file, result });
      }

      // Upload merged files from files-dir param
      for (const mergedFile of mergedFiles) {
        console.log(`Uploading merged file: ${path.basename(mergedFile)}`);
        const result = await uploadFiles([mergedFile], {
          workflowId,
          pipelineRunId,
          jobId,
          label,
          archivePath,
        });
        uploadResults.push({ file: mergedFile, result });
      }
    } finally {
      core.endGroup();
    }

    // Step 3: Set outputs
    core.startGroup("Step 3: Set outputs");
    try {
      const allSuccess = uploadResults.every(
        ({ result }) => result.status >= 200 && result.status < 300
      );
      const statusCodes = uploadResults
        .map(({ result }) => String(result.status))
        .join(", ");
      const responseSummary = uploadResults
        .map(({ file, result }) => ({
          file: path.basename(file),
          status: result.status,
          data: result.data,
        }));

      console.log("Execution outputs:");
      console.log(`  - total uploads: ${uploadResults.length}`);
      console.log(`  - status codes: ${statusCodes}`);
      if (allSuccess) {
        core.setOutput("success", "true");
        core.setOutput("status-code", statusCodes);
        core.setOutput("response-text", JSON.stringify(responseSummary));
        console.log("=".repeat(60));
        console.log("Metadata upload completed successfully");
        console.log("=".repeat(60));
      } else {
        const failed = uploadResults.filter(
          ({ result }) => result.status < 200 || result.status >= 300
        );
        core.setOutput("success", "false");
        core.setOutput("status-code", statusCodes);
        core.setOutput("response-text", JSON.stringify(responseSummary));
        core.error(
          `Upload failed for ${failed.length}/${uploadResults.length} files: ` +
            failed.map((f) => `${path.basename(f.file)}=${f.result.status}`).join(", ")
        );
        core.setFailed(
          `Upload failed for ${failed.length}/${uploadResults.length} files`
        );
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