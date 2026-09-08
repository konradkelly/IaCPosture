# IaCPosture — Technical Spec

**GitHub repo description:** DevSecOps/AppSec tool: Terraform security scanning, OWASP/CIS control mapping, and AI-assisted remediation with self-verification, built on serverless AWS.

**Version:** 0.1 (draft)
**Author:** Konrad Le-De Kelly
**Status:** Pre-build / architecture phase

---

## 1. Summary

An agentic system that scans Terraform infrastructure-as-code for security misconfigurations, IAM policy violations, and OWASP/CIS-mapped vulnerabilities, then proposes minimal, self-verified remediation diffs for human review. The system runs as a CI check on pull requests and never auto-merges — every finding and every proposed fix is presented to a human reviewer with full citations back to the specific rule and framework control it addresses.

**Core design principle:** the agent proposes, it never disposes. Deterministic tools do the finding; the LLM explains and drafts; a human approves.

---

## 2. Goals / Non-Goals

**Goals**
- Detect security misconfigurations in Terraform (network exposure, IAM over-permissioning, missing encryption, hardcoded secrets, unpinned module sources)
- Detect security misconfigurations in Kubernetes manifests and Helm charts (privileged containers, missing `runAsNonRoot`, host network/PID access, missing resource limits, overly broad RBAC) — **v2 scope, see §8**
- Map each finding to a specific control (OWASP CI/CD Top 10, OWASP Cloud-Native/IaC security guidance, CIS AWS Foundations Benchmark; CIS Kubernetes Benchmark added in v2 alongside K8s/Helm scanning)
- Propose minimal remediation diffs, self-verified against the same scanner that found the issue
- Run as a GitHub Action / PR check with a reviewable dashboard
- Produce measurable eval numbers (detection recall, fix acceptance rate)

**Non-Goals (v1)**
- Auto-merging any change without human approval
- Covering cloud providers beyond AWS
- Kubernetes manifests and Helm charts as scan targets — deferred to v2 once the Terraform path is proven (see §8); CloudFormation/Pulumi remain further out
- Deploying this project's own infrastructure on Kubernetes — the pipeline itself stays serverless (see §4); EKS/Helm, once added, refers to the *scan target*, not the *host*
- Full legal/compliance certification (SOC 2 audit-readiness claims) — this is a developer aid, not an auditor

---

## 3. Architecture Overview

```
                    ┌─────────────────────────────────────────────┐
                    │              GitHub PR Trigger               │
                    │         (terraform plan / PR diff)            │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 1 — Deterministic Scan (no LLM)        │
                    │   terraform-scanner Lambda: tfsec + Checkov    │
                    │   (v1)                                          │
                    │   k8s-scanner Lambda: kubesec + Checkov +      │
                    │     helm template — v2 addition, same          │
                    │     fan-out pattern by iac_type                │
                    │   → raw findings                                │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 2 — Framework Mapping Agent (Lambda)   │
                    │   finding → OWASP/CIS control + citation       │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 3 — Remediation Agent (Lambda)         │
                    │   finding → proposed diff → self-check rescan  │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 4 — Review Dashboard (API GW + React)  │
                    │   human approve / edit / reject → audit log    │
                    └─────────────────────────────────────────────────┘
```

---

## 4. AWS Architecture (DVA-C02-aligned)

The system is built as a serverless pipeline so it doubles as hands-on practice for AWS Developer Associate domains (Lambda, API Gateway, IAM, DynamoDB/RDS, event-driven design, deployment/CI-CD, monitoring).

### 4.1 Core resources

| Resource | Purpose | DVA-C02 domain |
|---|---|---|
| **API Gateway (REST or HTTP API)** | Public-facing endpoints for the review dashboard (fetch findings, submit review decisions) and the GitHub webhook receiver | Deployment, Security |
| **Lambda — `webhook-receiver`** | Validates GitHub webhook signature, extracts PR diff/Terraform files, drops job onto SQS | Development with AWS Services |
| **Lambda — `terraform-scanner`** | Runs tfsec + Checkov against Terraform files. Packaged with a shared Checkov Lambda layer + a tfsec-binary layer. **v1.** | Development, Deployment |
| **Lambda — `k8s-scanner`** | Runs `helm template` to render charts, then kubesec + Checkov against the rendered manifests. Packaged with the same shared Checkov layer + a kubesec/helm-binaries layer. **v2 — deferred until the Terraform path is proven; see §8.** | Development, Deployment |
| **Lambda — `mapping-agent`** | Calls Anthropic API with scanner findings, returns control-mapped findings (strict JSON schema) | Development, Security |
| **Lambda — `remediation-agent`** | Calls Anthropic API to draft a diff, then invokes `terraform-scanner` or `k8s-scanner` (by `iac_type`) to self-check the fix | Development, Security |
| **Lambda — `review-api`** | CRUD behind API Gateway for the dashboard: list findings, get diff, post approve/reject | Development with AWS Services |
| **SQS queue** | Decouples webhook ingestion from scan execution — a PR with many changed files shouldn't block the webhook response (GitHub expects a fast ACK) | Development, Deployment |
| **DynamoDB** *or* **RDS (Postgres)** | Findings, controls corpus, review audit log. DynamoDB fits the access pattern better (fetch by PR/finding ID) and is more idiomatic serverless; Postgres is a better fit if you want relational queries across the controls corpus. See §4.2 for the tradeoff. | Development with AWS Services |
| **S3** | Stores raw Terraform snapshots per scan run, scanner output artifacts, and the versioned control corpus (CIS/OWASP text) | Development, Deployment |
| **EventBridge** | Fan-out trigger for scheduled re-scans (e.g. nightly re-check of `main` against an updated CIS benchmark version) | Development with AWS Services |
| **IAM roles (per Lambda, least-privilege)** | Each Lambda gets a narrowly scoped execution role — `terraform-scanner` and `k8s-scanner` each get only the tooling/permissions their scan type needs, and neither gets `remediation-agent`'s permissions. This is itself a live demo of the least-privilege principle the tool checks for. | Security, Deployment |
| **Secrets Manager** | Anthropic API key, GitHub App private key/webhook secret | Security |
| **CloudWatch (Logs, Metrics, Alarms)** | Structured logs per Lambda, custom metric for findings-per-scan and fix-acceptance-rate, alarm on scan failures | Troubleshooting and Monitoring |
| **X-Ray** | Trace a webhook event end-to-end through the SQS → Lambda chain — useful for debugging latency in the self-check loop | Troubleshooting and Monitoring |
| **CloudFront + S3 (static hosting)** | Hosts the review dashboard (React + Vite + TypeScript) | Deployment |
| **Cognito** | Auth for the review dashboard and its API. Pulled forward from the original v1.1 plan (see §8): the API exposes real vulnerability findings and a route that resolves them, and an unauthenticated write endpoint plus a self-asserted audit-trail actor were both live problems the moment the dashboard went internet-facing, not multi-tenant-only ones. | Security |

### 4.2 Data store decision

**Decided: DynamoDB.** Single-table design keyed on `PR#<id>` / `FINDING#<id>`, fits Lambda's stateless request pattern well, no VPC/connection-pooling concerns, cheaper at low volume. GSIs will be added per query pattern as they come up (e.g. a `control_id` GSI for "show me all findings mapped to CIS 1.16 across every scan this month"). If ad-hoc analytical queries across the controls corpus become a real need later, a small Postgres+pgvector instance can be added alongside for that piece specifically, rather than migrating the whole findings store.

**Recommendation for v1:** DynamoDB for findings/audit-log (matches the event-driven access pattern and avoids VPC complexity for the Lambda chain), S3 for the versioned control corpus text. If you later add embedding-based retrieval over the corpus, add a small Postgres+pgvector instance just for that piece rather than migrating everything — a hybrid is fine and is itself a defensible architecture decision to explain in an interview.

### 4.3 Scanner packaging decision

**Decided: Lambda layers.** `terraform-scanner` ships in v1; `k8s-scanner` is added in v2 (see §8) using the same pattern, so the shared layer is designed for both from the start.

Splitting the scan stage by `iac_type` (rather than one Lambda running every tool) keeps each function's dependencies small enough for layers — Checkov's Python dependency tree is the heavy piece, and it's the only tool needed on both sides, so it's built as a shared layer once and reused when `k8s-scanner` is added:

- **Shared layer:** Checkov (Python package + deps) — built in v1 for `terraform-scanner`, reattached to `k8s-scanner` unchanged in v2
- **`terraform-scanner`-only layer (v1):** tfsec (single static Go binary)
- **`k8s-scanner`-only layer (v2):** kubesec + `helm` CLI (both single static Go binaries)

Each function stays comfortably under the layer size ceiling, and layer versions can be bumped independently per tool without touching the other scanner. This also gets more direct DVA-C02-relevant reps with Lambda layers and their versioning/size-limit behavior than a container-image approach would.

### 4.4 Event flow (detail) — v1 (Terraform only)

1. GitHub PR opened/updated → webhook → **API Gateway** → **`webhook-receiver` Lambda**
2. `webhook-receiver` verifies HMAC signature, pulls changed `.tf` files via GitHub API, tags each with `iac_type: terraform`, writes raw files to **S3**, drops `{pr_id, s3_key, iac_type}` onto **SQS**
3. **`terraform-scanner` Lambda** runs tfsec + Checkov, writes raw findings to **DynamoDB** (`status: raw`)
4. DynamoDB stream (or a second SQS hop) triggers **`mapping-agent` Lambda** — for each raw finding, calls Anthropic API with the finding + relevant control corpus excerpt (pulled from S3), writes back `status: mapped` with control citation
5. **`remediation-agent` Lambda** triggered per mapped finding — drafts a diff via Anthropic API, then invokes `terraform-scanner` to self-check the fix against the patched file, sets `self_check_passed: true/false`, writes `status: fix-proposed` or `status: needs-human-only` if self-check fails
6. Reviewer opens dashboard (**CloudFront** → React app → **API Gateway** → **`review-api` Lambda** → DynamoDB) — approves/edits/rejects
7. On approval, `review-api` Lambda calls GitHub API to push the diff as a suggested change / commit on the PR branch
8. Every step writes a `review_event` / `audit_log` entry — nothing is silently decided

**v2 change:** step 2 tags K8s/Helm files as `k8s-manifest`/`helm` too, `webhook-receiver` fans out to `k8s-scanner` alongside `terraform-scanner`, and step 5's self-check routes by `iac_type` to whichever scanner matches. `mapping-agent`, `remediation-agent`, `review-api`, and the dashboard require no changes — the fan-out is isolated entirely to the scan stage, which is the point of splitting it into two Lambdas now rather than later.

---

## 5. Data Model

Both item types below live in a **single DynamoDB table**, not two separate tables — this is the standard single-table design pattern for DynamoDB, where distinct entity types are distinguished by their key prefixes (`PR#`/`FINDING#` vs `PR#…#FINDING#`/`EVENT#`) rather than by separate tables. This keeps related data queryable together (e.g. everything under one `PR#<pr_id>` partition) and avoids the cross-table joins DynamoDB isn't designed for.

```
FindingRecord (DynamoDB)
├── pk: PR#<pr_id>
├── sk: FINDING#<finding_id>
├── iac_type: "terraform" | "k8s-manifest" | "helm"
├── source: "tfsec" | "checkov" | "kubesec"
├── rule_id: string
├── file, line_range
├── severity
├── control_mappings: [{ framework: "CIS-AWS" | "CIS-Kubernetes" | "OWASP-CICD" | "OWASP-CloudNative", control_id, control_text_ref (S3 key), citation_span }]
├── status: raw | mapped | fix-proposed | needs-human-only | resolved
├── proposed_fix: { diff, rationale, self_check_passed, cleared, self_check_new_findings: [], agent_diff? }
└── created_at, updated_at

ReviewEvent (DynamoDB)
├── pk: PR#<pr_id>#FINDING#<finding_id>
├── sk: EVENT#<timestamp>
├── actor: reviewer id (from the verified JWT, never the request body)
├── action: approved | edited | rejected
├── edited_diff: the reviewer's diff, on an "edited" action
└── notes
```

**Why `ReviewEvent.pk` carries `pr_id`.** An earlier draft keyed it on
`FINDING#<finding_id>` alone. That is unsound: `finding_id` is a content hash
of the finding, so the same rule on the same file yields the *same* id in
every PR that scans it — ids are unique within a PR, not across them. Keyed on
the id alone, a decision recorded against one PR appears in the audit trail of
every other PR containing that finding, attributing decisions nobody made
there. This was observed in practice, with one approval on `demo-1` showing up
against `manual-test-1`. For a log whose entire purpose is that nothing is
silently decided, misattribution is the one defect it cannot tolerate.

**On `proposed_fix`:** `cleared` records whether the rescan confirmed the
original finding gone, separately from `self_check_passed`, which also
requires that no new findings appeared — a fix can clear the original and
still fail, and the two failure modes need telling apart (§8.1). `agent_diff`
preserves the agent's original diff the first time a reviewer edits the fix,
so fix-acceptance (§7) stays measurable after an edit.

---

## 6. Agent Contracts (strict JSON schemas)

Both LLM-calling Lambdas constrain output to schema-validated JSON — no free text accepted downstream.

**Mapping agent output:**
```json
{
  "finding_id": "string",
  "control_id": "string",
  "framework": "CIS-AWS-1.4 | OWASP-CICD-Top10 | OWASP-CloudNative",
  "citation": "verbatim short excerpt, <15 words, from control text",
  "rationale": "1-2 sentences, must reference the finding's rule_id"
}
```

**Remediation agent output:**
```json
{
  "finding_id": "string",
  "diff": "unified diff format only",
  "rationale": "string",
  "self_check_passed": "boolean — set by code, not the LLM",
  "self_check_new_findings": ["array of any new rule_ids introduced by the fix"]
}
```

`self_check_passed` is **never** an LLM-asserted field — it's computed by re-running the deterministic scanner against the patched file and comparing findings before/after in code. This is the single most important integrity guarantee in the system.

**Suppression comments defeat that guarantee, and must be rejected in code.** The self-check asks "does the scanner still report this finding?", so a diff that merely silences the rule — `#tfsec:ignore:`, `#checkov:skip=`, `trivy:ignore`, `nosec` — clears the finding, introduces nothing new, and comes back `self_check_passed: true`. The agent earns a scanner-verified badge for changing no infrastructure at all.

This is not hypothetical. On the first run against real code (PugetScope, §7), asked to fix a CRITICAL `0.0.0.0/0` ingress rule, the agent left the CIDR untouched and added `#tfsec:ignore:aws-ec2-no-public-ingress-sgr` twice, with a fluent justification comment. It failed the self-check only by accident: that file held three instances of the rule, so the rescan still reported the pair. In a single-instance file it would have passed and been presented to a reviewer as verified.

Two consequences, both now implemented in `remediation-agent`:

- The prompt forbids suppressions **and** `_find_added_suppressions` enforces it on the diff's added lines, refusing the fix before the scanner ever runs. Prompt-only would be trusting the model's output, which is precisely what this project exists not to do. Pre-existing suppressions are the author's decision and are left alone.
- The before/after comparison counts **occurrences** per `(source, rule_id)` rather than testing presence, so "one of three instances was fixed" is distinguishable from "none were". Note this removes the accident above — which is exactly why the suppression check has to be a hard gate rather than advisory.

This also qualifies §8.1's admission rule. "The scanner's rule *is* the vulnerability" holds for what the rule *matches*, but every scanner ships an escape hatch that stops it matching without changing the infrastructure. Any scanner class admitted in future needs its suppression syntax added to `SUPPRESSION_MARKERS` before its fixes can be trusted.

### 6.1 The self-check proves security posture, not functional correctness

A clean rescan proves the finding is gone. It cannot prove the infrastructure still works, and nothing downstream should read it as though it does.

The sharpest illustration, again from the first real-code run: asked to fix an open port 80 ingress rule, the agent deleted the rule and stated in its rationale that certificate issuance used DNS-01. PugetScope's cert-manager `ClusterIssuer` uses ACME **HTTP-01**, which requires inbound port 80. The fix would have broken TLS renewal roughly 60 days later — long after anyone would connect the outage to a security fix. It passed the self-check cleanly, because deleting the rule genuinely removes the finding.

Two structural consequences, both enforced in `remediation-agent` rather than requested in the prompt:

- **Deletions are held for review.** `_find_dropped_resources` compares resource-block counts per *type* between the original and corrected file. A net decrease forces `needs-human-only` however clean the rescan. Comparison is per type, not per address, so a rename (a delete plus an add — as in a legitimate `nodeport_from_internet` → `nodeport_from_admin` rescope) is not mistaken for a deletion.
- **Unverifiable claims are declared, not buried.** `assumptions` is a required field on the agent's output schema, and a non-empty list forces `needs-human-only`. The agent sees exactly one file, so any claim about how the wider system behaves is a guess; the schema makes it a visible, checkable guess instead of confident prose.

**Calibrating `assumptions` mattered as much as adding it.** Defined as "every fact you could not verify," even a self-contained fix (adding an SSE block to a bucket) declared four — provider versions, style preferences, *"SSE-S3 is transparent to clients"* — so nothing ever passed and `fix-proposed` became an empty category. A gate that catches everything discriminates nothing, and a reviewer trained to skim four bullets of boilerplate is a reviewer who will skim the one that matters. The definition is therefore **consequence-based**: an assumption qualifies only if it is unverifiable from the file *and* its falsity would break the running system or leave the finding unfixed. Measured either side of that change:

| Case | "unverifiable" wording | consequence wording |
|---|---|---|
| S3 encryption (self-contained) | 4 assumptions, held | **0 assumptions, passes** |
| Port 80 (depends on unseen ACME config) | 4 assumptions, held | **2 assumptions, held** — and both are real |

The surviving port-80 assumption names ACME HTTP-01 explicitly, so the fix now arrives with its own falsification test attached.

**On division of labour between prompt and code.** The prompt is what changed the agent's *behaviour* — it stopped suppressing, and started constraining rather than deleting. The code gates are what make that behaviour non-optional. As of this writing neither the suppression nor the deletion gate has fired in production, because the prompt has so far prevented the behaviour they guard against; they are proven by unit tests against the real captured diffs. That is the intended arrangement, not a redundancy: a prompt is a request, and the project's premise is that the model's output is checked by code rather than trusted.

---

## 7. Eval Plan

1. **Detection recall**: labeled set of ~30-50 Terraform snippets with known injected vulnerabilities (drawn from CIS benchmark examples + hand-crafted edge cases) — measure what fraction Layer 1 + Layer 2 correctly find and correctly map. In v2, extend with ~15-20 hand-crafted/AI-generated Kubernetes manifest/Helm chart snippets and report recall per `iac_type`.
2. **Remediation safety**: for every proposed fix in the labeled set, measure (a) does self-check confirm the original finding cleared, (b) does the fix introduce any new findings
3. **Fix acceptance rate**: once running against real PRs, track approved-unedited vs edited vs rejected per fix — the headline metric for the project writeup

---

## 8. Build Phases

| Phase | Scope |
|---|---|
| **v1 — Terraform only, read-only scan + suggest** | `terraform-scanner` + Layers 2-3 running on manual trigger (CLI or simple upload), findings + proposed diffs shown in dashboard, no GitHub write-back. Fastest path to a complete, demoable project — proves the whole pipeline (scan → map → remediate → self-check → review) on one IaC type before adding scope. Dashboard and review API ship behind Cognito from the start (see below) rather than as a later add-on. |
| **v2 — Add Kubernetes/Helm scanning** | `k8s-scanner` Lambda added alongside `terraform-scanner`, same shared Checkov layer, `webhook-receiver`/`mapping-agent`/`remediation-agent`/dashboard unchanged (see §4.4). CIS Kubernetes Benchmark + OWASP Cloud-Native guidance added to the control corpus. |
| **v3 — CI integration** | GitHub App/webhook, PR-triggered scans, diff suggestions posted as PR comments |
| **v4 — Write-back on approval** | Approved fixes committed to PR branch automatically |

**Recommended sequencing given your Feb–June 2027 timeline:** ship v1 first as a complete, demoable artifact — Terraform-only already exercises every DVA-C02-relevant AWS resource in §4.1 except `k8s-scanner` itself. Add v2 (K8s/Helm) once v1's eval numbers (§7) are solid, then invest in v3's GitHub App plumbing last, since it's the most infra-heavy phase for the least new agent-architecture learning.

---

## 9. Team Workflow

Two-person split: infra/deployment + `mapping-agent` (Konrad) vs. `remediation-agent` + scanner integration + frontend (partner). Ownership divide:

- **Konrad owns**: everything AWS-native — API Gateway, SQS, DynamoDB tables, IAM roles/policies, Lambda deployment and packaging (layers), CloudWatch/X-Ray, CI/CD, Secrets Manager, AWS account itself — plus `mapping-agent`'s prompt design and schema-validated JSON output
- **Partner owns**: `terraform-scanner`'s scanning logic (tfsec/Checkov invocation, parsing into `FindingRecord` shape), `remediation-agent`'s prompt design + diff generation + self-check integration, the review dashboard frontend (React + Vite + TypeScript), and the eval harness (§7)

**Workflow: independent development, merged via Git.** Partner builds against the schemas in §5 (`FindingRecord`) and §6 (agent JSON contracts) without needing AWS account access at all — no stub Lambdas to deploy, no IAM to grant, no sequencing dependency on Konrad's deploy schedule. Both people branch off the shared contracts, build independently, and merge. Merge conflicts in code are expected and fine to resolve as they come up.

**What Git merges catch, and what they don't:** a clean merge only guarantees the *code* combined without textual conflicts — it says nothing about whether partner's `remediation-agent` still matches the live `FindingRecord` shape or DynamoDB table structure if either changed since he last pulled. That's a runtime failure, not a merge-time one. Since this workflow trades away the "test against something real" benefit for speed and independence, the shared schemas in §5–§6 are the thing actually keeping both halves compatible between merges — treat any change to either as something to flag to the other person immediately, not just commit and move on.

**Recommended lightweight guardrails**, given no live integration testing until deploy:
- Version the schemas (§5, §6) in the repo itself (e.g. a `schemas/` folder with the JSON Schema definitions), so a schema change shows up as a reviewable diff, not a Slack message that's easy to miss
- Partner mocks `FindingRecord` inputs locally against the versioned schema for `remediation-agent` development — a small `fixtures/` folder of example findings works fine
- Konrad does a real integration pass (deploy partner's merged code, run it against actual DynamoDB data) before treating a milestone as "done," rather than assuming merge success equals working system

**Branching model.** Component ownership maps directly onto branches, which keeps conflicts scoped and predictable:

- `main` — always deployable; only merged into via PR, never pushed to directly
- `infra/*` (Konrad) — e.g. `infra/dynamo-schema`, `infra/api-gateway`, `infra/scanner-lambda-deploy`; touches Terraform/SAM/CDK for the AWS resources, plus `mapping-agent`'s Lambda code
- `agent/remediation` (partner) — `remediation-agent` prompt design, diff generation, self-check integration
- `scanner/terraform` (partner) — `terraform-scanner` scanning logic and `FindingRecord` parsing
- `frontend/dashboard` (partner) — React/Vite/TypeScript review dashboard

Because the two people's branches touch almost entirely different files (infra/deploy code vs. application logic vs. frontend), most merges into `main` should be conflict-free by construction. The place conflicts *will* happen is the shared schema files (`schemas/finding-record.json`, the agent contract schemas from §6) if both people are mid-change on them at once — treat those as a short-lived shared branch or just communicate before editing them, rather than letting them drift on two long-lived feature branches.

A couple of practical rules worth setting explicitly:
- PR into `main` requires the other person's review, even async — this is the actual substitute for the integration testing you're giving up by not deploying incrementally
- Rebase feature branches on `main` regularly rather than letting them diverge for weeks; the longer a branch lives, the more likely its assumptions about the schema have quietly gone stale
- Tag or note in the PR description which version of the schema a branch was built against, so a stale-schema conflict is easy to spot at review time instead of only surfacing at runtime

## 10. Open Decisions

- [x] DynamoDB vs Postgres for findings store — **Decided: DynamoDB** (see §4.2)
- [x] Container image Lambda vs Lambda layer for packaging scanner binaries — **Decided: Lambda layers**, split across `terraform-scanner` and `k8s-scanner` (see §4.3)
- [x] Whether `remediation-agent` and `mapping-agent` should be separate Lambdas or one Lambda with two code paths — **Decided: separate Lambdas**, each with its own least-privilege IAM role (distinct roles per agent is itself part of the project's security story)
- [x] Whether Kubernetes/Helm scanning ships in v1 alongside Terraform, or lands as a later addition — **Decided: v1 is Terraform-only**; K8s/Helm scanning is v2, added once the Terraform path's eval numbers are proven (see §8)
- [x] Where sample K8s manifests/Helm charts for the eval set come from — **Decided: hand-crafted/AI-generated**, not sourced from PugetScope's live cluster config (keeps the eval set's known-vulnerability labels clean and independent of production infra)

