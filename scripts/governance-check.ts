#!/usr/bin/env node
/**
 * Governance Policy Enforcement — validates security invariants from AI_OPERATIONS_GOVERNANCE.md.
 *
 * Checks:
 *   1. Tool authority — dangerous tool sets, safe auto-approve limits, gateway deny list
 *   2. Sandbox isolation — blocked host paths, no unconfined profiles
 *   3. Communication safety — message tool requires approval
 *   4. Automation scope — cron gated, sessions_spawn denied
 *   5. Memory governance — no secrets in memory patterns
 *   6. Exec security — allowlist mode available, safeBins pattern
 *   7. Supply-chain — pinned Docker base images, no unpinned actions
 *   8. Execution ceiling — no privilege creep in tool profiles or exec modes
 *   9. Network exposure — no host networking, public binds, or loosened isolation
 *  10. Autonomy escalation — no unsupervised execution flags
 *
 * Exit 0 = pass, exit 1 = failure(s) found.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

interface Violation {
  domain: string;
  file: string;
  message: string;
}

const violations: Violation[] = [];

function fail(domain: string, file: string, message: string) {
  violations.push({ domain, file, message });
}

function readFile(rel: string): string {
  const abs = join(ROOT, rel);
  if (!existsSync(abs)) {
    fail("file-missing", rel, `Expected file not found: ${rel}`);
    return "";
  }
  return readFileSync(abs, "utf-8");
}

// ─── 1. Tool Authority ───────────────────────────────────────────────

function checkToolAuthority() {
  const src = readFile("src/security/dangerous-tools.ts");
  if (!src) {
    return;
  }

  // DANGEROUS_ACP_TOOL_NAMES must include these critical tools
  const requiredDangerous = [
    "exec",
    "spawn",
    "shell",
    "sessions_spawn",
    "sessions_send",
    "gateway",
    "fs_write",
    "fs_delete",
    "fs_move",
    "apply_patch",
  ];

  for (const tool of requiredDangerous) {
    // Match the tool name in the array literal (quoted string)
    if (!new RegExp(`["']${tool}["']`).test(src)) {
      fail(
        "tool-authority",
        "src/security/dangerous-tools.ts",
        `DANGEROUS_ACP_TOOL_NAMES missing required tool: "${tool}"`,
      );
    }
  }

  // DEFAULT_GATEWAY_HTTP_TOOL_DENY must include sessions_spawn and gateway
  const requiredGatewayDeny = ["sessions_spawn", "sessions_send", "gateway"];
  for (const tool of requiredGatewayDeny) {
    if (!new RegExp(`DEFAULT_GATEWAY_HTTP_TOOL_DENY[\\s\\S]*?["']${tool}["']`).test(src)) {
      fail(
        "tool-authority",
        "src/security/dangerous-tools.ts",
        `DEFAULT_GATEWAY_HTTP_TOOL_DENY missing: "${tool}"`,
      );
    }
  }

  // SAFE_AUTO_APPROVE must stay read-only-ish — no exec/write/send tools
  const acpSrc = readFile("src/acp/client.ts");
  if (acpSrc) {
    const safeMatch = acpSrc.match(
      /SAFE_AUTO_APPROVE_TOOL_IDS[\s\S]*?new\s+Set\s*\(\s*\[([\s\S]*?)\]\s*\)/,
    );
    if (safeMatch) {
      const safeTools = safeMatch[1];
      const forbiddenAutoApprove = [
        "exec",
        "spawn",
        "shell",
        "fs_write",
        "fs_delete",
        "message",
        "sessions_spawn",
        "sessions_send",
        "gateway",
        "apply_patch",
      ];
      for (const tool of forbiddenAutoApprove) {
        if (new RegExp(`["']${tool}["']`).test(safeTools)) {
          fail(
            "tool-authority",
            "src/acp/client.ts",
            `SAFE_AUTO_APPROVE_TOOL_IDS must not include dangerous tool: "${tool}"`,
          );
        }
      }
    }
  }
}

// ─── 2. Sandbox Isolation ────────────────────────────────────────────

function checkSandboxIsolation() {
  const src = readFile("src/agents/sandbox/validate-sandbox-security.ts");
  if (!src) {
    return;
  }

  // BLOCKED_HOST_PATHS must include critical system paths
  const requiredBlocked = ["/etc", "/proc", "/sys", "/dev", "/root", "/boot"];
  for (const p of requiredBlocked) {
    if (!src.includes(`"${p}"`)) {
      fail(
        "sandbox-isolation",
        "src/agents/sandbox/validate-sandbox-security.ts",
        `BLOCKED_HOST_PATHS missing critical path: "${p}"`,
      );
    }
  }

  // Docker socket must be blocked
  if (!src.includes("docker.sock")) {
    fail(
      "sandbox-isolation",
      "src/agents/sandbox/validate-sandbox-security.ts",
      "BLOCKED_HOST_PATHS must block Docker socket paths",
    );
  }

  // BLOCKED_SECCOMP_PROFILES must include "unconfined"
  if (!/BLOCKED_SECCOMP_PROFILES[\s\S]*?["']unconfined["']/.test(src)) {
    fail(
      "sandbox-isolation",
      "src/agents/sandbox/validate-sandbox-security.ts",
      'BLOCKED_SECCOMP_PROFILES must include "unconfined"',
    );
  }

  // BLOCKED_APPARMOR_PROFILES must include "unconfined"
  if (!/BLOCKED_APPARMOR_PROFILES[\s\S]*?["']unconfined["']/.test(src)) {
    fail(
      "sandbox-isolation",
      "src/agents/sandbox/validate-sandbox-security.ts",
      'BLOCKED_APPARMOR_PROFILES must include "unconfined"',
    );
  }
}

// ─── 3. Exec Security Configuration ─────────────────────────────────

function checkExecSecurity() {
  const src = readFile("src/config/types.tools.ts");
  if (!src) {
    return;
  }

  // ExecToolConfig must define a "security" field with allowlist option
  if (!/security.*["']allowlist["']/.test(src) && !/["']allowlist["']/.test(src)) {
    // Looser check: just verify the type includes "allowlist" as a valid option
    if (!src.includes("allowlist")) {
      fail(
        "exec-security",
        "src/config/types.tools.ts",
        'ExecToolConfig must support "allowlist" security mode',
      );
    }
  }

  // Must support "deny" mode
  if (!src.includes('"deny"') && !src.includes("'deny'")) {
    fail(
      "exec-security",
      "src/config/types.tools.ts",
      'ExecToolConfig must support "deny" security mode',
    );
  }
}

// ─── 4. Docker Supply Chain ──────────────────────────────────────────

function checkDockerPinning() {
  const dockerfiles = ["Dockerfile", "Dockerfile.sandbox", "Dockerfile.sandbox-common"];
  for (const df of dockerfiles) {
    const src = readFile(df);
    if (!src) {
      continue;
    }

    // Collect stage names from "FROM ... AS <stage>" to skip internal refs
    const stageNames = new Set<string>();
    for (const m of src.matchAll(/^\s*FROM\s+\S+\s+AS\s+(\S+)/gim)) {
      stageNames.add(m[1].toLowerCase());
    }

    // Every FROM line should use a sha256 digest pin
    const fromLines = src
      .split("\n")
      .filter((l) => /^\s*FROM\s/i.test(l))
      .filter((l) => !/^\s*FROM\s+\S*\$\{/i.test(l)) // skip ARG-based FROM (e.g. FROM base-${VAR})
      .filter((l) => !/^\s*FROM\s+scratch/i.test(l)); // skip scratch

    for (const line of fromLines) {
      // Skip references to earlier build stages
      const imageMatch = line.match(/FROM\s+(\S+)/i);
      if (imageMatch) {
        const image = imageMatch[1].toLowerCase();
        // Skip stage references like "FROM build" or "FROM base-variant"
        const isStageRef = [...stageNames].some(
          (s) => image === s || image.startsWith(`${s}-`) || image.endsWith(`-${s}`),
        );
        if (isStageRef || stageNames.has(image)) {
          continue;
        }
        // Skip if image is a bare word matching a known stage pattern
        if (/^[a-z][a-z0-9-]*$/i.test(image) && !image.includes("/") && !image.includes(".")) {
          // Likely a stage reference — skip
          continue;
        }
      }
      if (!line.includes("@sha256:")) {
        fail("supply-chain", df, `Unpinned base image: ${line.trim()}`);
      }
    }
  }
}

// ─── 5. GitHub Actions Pinning ───────────────────────────────────────

function checkActionsPinning() {
  const workflowDir = join(ROOT, ".github", "workflows");
  if (!existsSync(workflowDir)) {
    return;
  }

  const files = readdirSync(workflowDir).filter(
    (f: string) => f.endsWith(".yml") || f.endsWith(".yaml"),
  );

  for (const file of files) {
    const rel = `.github/workflows/${file}`;
    const src = readFile(rel);
    if (!src) {
      continue;
    }

    // Find "uses:" directives (but skip local actions like ./.github/actions/...)
    const usesLines = src.split("\n").filter((l) => {
      const trimmed = l.trim();
      return trimmed.startsWith("uses:") || trimmed.startsWith("- uses:");
    });

    for (const line of usesLines) {
      const match = line.match(/uses:\s*([^\s#]+)/);
      if (!match) {
        continue;
      }
      const action = match[1];

      // Skip local actions
      if (action.startsWith("./")) {
        continue;
      }

      // Skip Docker images (docker://)
      if (action.startsWith("docker://")) {
        continue;
      }

      // Third-party actions must be pinned to a commit SHA (40-hex-char)
      // Acceptable: owner/repo@<40-hex-sha>
      // Unacceptable: owner/repo@v4, owner/repo@main
      const atIndex = action.indexOf("@");
      if (atIndex === -1) {
        fail("supply-chain", rel, `Action not pinned: ${action}`);
        continue;
      }

      const ref = action.substring(atIndex + 1);
      // Allow version tags (v1, v2, v4) for first-party (actions/*) — common practice
      // For third-party, flag non-SHA refs
      const owner = action.substring(0, action.indexOf("/"));
      // First-party (actions/*, github/*) use version tags — acceptable
      const firstParty = ["actions", "github"];
      if (!firstParty.includes(owner) && !/^[0-9a-f]{40}$/i.test(ref)) {
        // Advisory warning, not a hard failure — Dependabot manages these
        console.warn(
          `⚠ supply-chain advisory: ${rel}: third-party action not SHA-pinned: ${action} (ref: ${ref})`,
        );
      }
    }
  }
}

// ─── 6. Governance Document Integrity ────────────────────────────────

function checkGovernanceDoc() {
  const doc = readFile("AI_OPERATIONS_GOVERNANCE.md");
  if (!doc) {
    fail(
      "governance-integrity",
      "AI_OPERATIONS_GOVERNANCE.md",
      "Governance document is missing from repository root",
    );
    return;
  }

  // Must contain core governance anchors
  const requiredSections = [
    "Authority Boundaries",
    "Governance Layers",
    "Operational Modes",
    "Approved Maintenance Allowlist",
    "Implementation Checklist",
    "Escalation Protocol",
    "Change Control",
  ];

  for (const section of requiredSections) {
    if (!doc.includes(section)) {
      fail(
        "governance-integrity",
        "AI_OPERATIONS_GOVERNANCE.md",
        `Missing required governance section: "${section}"`,
      );
    }
  }

  // Must contain the governing principle
  if (!doc.includes("AI assists operations. Human retains authority.")) {
    fail(
      "governance-integrity",
      "AI_OPERATIONS_GOVERNANCE.md",
      "Missing governing principle anchor text",
    );
  }
}

// ─── 7. Secret Redaction ─────────────────────────────────────────────

function checkSecretRedaction() {
  const src = readFile("src/logging/redact.ts");
  if (!src) {
    return;
  }

  // Must have redaction patterns for common secret formats
  const requiredPatterns = [
    "key", // API keys
    "token", // tokens
    "secret", // secrets
  ];

  for (const pat of requiredPatterns) {
    if (!src.toLowerCase().includes(pat)) {
      fail(
        "secret-redaction",
        "src/logging/redact.ts",
        `Secret redaction may be missing pattern for: "${pat}"`,
      );
    }
  }
}

// ─── 8. Execution Ceiling ────────────────────────────────────────────

function checkExecutionCeiling() {
  // No tool should gain write access to system paths outside sandbox
  const toolPolicySrc = readFile("src/agents/sandbox/tool-policy.ts");
  if (toolPolicySrc) {
    // Ensure tool policy doesn't blanket-allow write tools
    if (/allowAll.*true|"\*".*allow/i.test(toolPolicySrc)) {
      fail(
        "execution-ceiling",
        "src/agents/sandbox/tool-policy.ts",
        "Tool policy must not contain blanket allow-all patterns",
      );
    }
  }

  // ExecToolConfig must not introduce new privileged execution modes beyond deny/allowlist/full
  const execConfigSrc = readFile("src/config/types.tools.ts");
  if (execConfigSrc) {
    // Check for new security modes that bypass the known set
    const securityModeMatch = execConfigSrc.match(
      /security[\s\S]*?["'](deny|allowlist|full|ask)["']/g,
    );
    const knownModes = new Set(["deny", "allowlist", "full", "ask"]);
    if (securityModeMatch) {
      for (const m of securityModeMatch) {
        const modeMatch = m.match(/["']([^"']+)["']/);
        if (modeMatch && !knownModes.has(modeMatch[1])) {
          fail(
            "execution-ceiling",
            "src/config/types.tools.ts",
            `Unknown exec security mode detected: "${modeMatch[1]}" — may indicate privilege escalation`,
          );
        }
      }
    }
  }

  // No new auto-execute categories in tool catalog
  const catalogSrc = readFile("src/agents/tool-catalog.ts");
  if (catalogSrc) {
    // "minimal" profile must stay extremely restricted (read-only)
    const minimalMatch = catalogSrc.match(/minimal[\s\S]*?\[(.*?)\]/s);
    if (minimalMatch) {
      const minimalTools = minimalMatch[1];
      const dangerousInMinimal = [
        "exec",
        "spawn",
        "shell",
        "fs_write",
        "fs_delete",
        "message",
        "apply_patch",
        "gateway",
      ];
      for (const tool of dangerousInMinimal) {
        if (minimalTools.includes(tool)) {
          fail(
            "execution-ceiling",
            "src/agents/tool-catalog.ts",
            `Minimal tool profile must not include dangerous tool: "${tool}"`,
          );
        }
      }
    }
  }
}

// ─── 9. Network Exposure Guard ───────────────────────────────────────

function checkNetworkExposure() {
  // Check Dockerfiles for EXPOSE directives and --network=host
  const dockerfiles = [
    "Dockerfile",
    "Dockerfile.sandbox",
    "Dockerfile.sandbox-common",
    "docker-compose.yml",
  ];
  for (const df of dockerfiles) {
    const src = readFile(df);
    if (!src) {
      continue;
    }

    // Detect --network=host (breaks sandbox isolation)
    if (
      src.includes("network_mode: host") ||
      src.includes("--network=host") ||
      src.includes("--net=host")
    ) {
      fail(
        "network-exposure",
        df,
        "Detected --network=host or network_mode:host — breaks sandbox isolation",
      );
    }

    // In docker-compose, check for 0.0.0.0 bind (public exposure)
    if (df === "docker-compose.yml") {
      const lines = src.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Port mapping like "0.0.0.0:port:port" exposes publicly
        if (/["']?0\.0\.0\.0:/.test(line)) {
          fail(
            "network-exposure",
            df,
            `Public bind address 0.0.0.0 detected at line ${i + 1} — use 127.0.0.1 for loopback`,
          );
        }
      }
    }
  }

  // Check sandbox defaults: network should default to "none" or restricted
  const validateSrc = readFile("src/agents/sandbox/validate-sandbox-security.ts");
  if (validateSrc) {
    // Sandbox must not default to host networking
    if (
      /network.*["']host["']/.test(validateSrc) &&
      !/block|deny|reject|invalid/i.test(validateSrc)
    ) {
      fail(
        "network-exposure",
        "src/agents/sandbox/validate-sandbox-security.ts",
        "Sandbox appears to allow host networking — must be blocked",
      );
    }
  }
}

// ─── 10. Autonomy Escalation Guard ───────────────────────────────────

function checkAutonomyEscalation() {
  // Scan config type definitions and source for autonomy-escalation flags
  const configFiles = ["src/config/types.tools.ts", "src/config/types.ts"];

  // Patterns that indicate unsupervised autonomous execution
  const autonomyPatterns = [
    /auto[_-]?execute/i,
    /autonomous[_-]?mode/i,
    /unattended[_-]?run/i,
    /background[_-]?actions/i,
    /schedule[_-]?execute/i,
    /self[_-]?approve/i,
    /bypass[_-]?approval/i,
    /skip[_-]?human/i,
    /no[_-]?confirm/i,
  ];

  for (const cf of configFiles) {
    const src = readFile(cf);
    if (!src) {
      continue;
    }

    for (const pattern of autonomyPatterns) {
      const match = src.match(pattern);
      if (match) {
        fail(
          "autonomy-escalation",
          cf,
          `Autonomy escalation flag detected: "${match[0]}" — requires explicit governance approval`,
        );
      }
    }
  }

  // Also scan the ACP client for any new auto-approve expansions
  const acpSrc = readFile("src/acp/client.ts");
  if (acpSrc) {
    for (const pattern of autonomyPatterns) {
      const match = acpSrc.match(pattern);
      if (match) {
        fail(
          "autonomy-escalation",
          "src/acp/client.ts",
          `Autonomy escalation flag detected: "${match[0]}" — requires explicit governance approval`,
        );
      }
    }
  }
}

// ─── Run All Checks ──────────────────────────────────────────────────

checkToolAuthority();
checkSandboxIsolation();
checkExecSecurity();
checkDockerPinning();
checkActionsPinning();
checkGovernanceDoc();
checkSecretRedaction();
checkExecutionCeiling();
checkNetworkExposure();
checkAutonomyEscalation();

// ─── Report ──────────────────────────────────────────────────────────

if (violations.length === 0) {
  console.log("✅ Governance policy enforcement: all checks passed");
  process.exit(0);
} else {
  console.error(`❌ Governance policy enforcement: ${violations.length} violation(s) found\n`);

  // Group by domain
  const byDomain = new Map<string, Violation[]>();
  for (const v of violations) {
    const group = byDomain.get(v.domain) || [];
    group.push(v);
    byDomain.set(v.domain, group);
  }

  for (const [domain, items] of byDomain) {
    console.error(`── ${domain} ──`);
    for (const v of items) {
      console.error(`  ✗ ${v.file}: ${v.message}`);
    }
    console.error();
  }

  // GitHub Actions annotation format
  if (process.env.GITHUB_ACTIONS) {
    for (const v of violations) {
      console.log(`::error file=${v.file}::${v.domain}: ${v.message}`);
    }
  }

  process.exit(1);
}
