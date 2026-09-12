# Detection-recall eval for `terraform-scanner`

Spec §7.1, §8.2 item 1. Labelled Terraform cases with known injected
vulnerabilities, one command that scans them against the **deployed** scanner
and reports what fraction of the expected findings fired.

```
python run_eval.py                          # bucket from `terraform output`
python run_eval.py --report results.json    # keep the full per-case result
python run_eval.py --keep                   # leave the S3 prefix for inspection
```

Needs `boto3`, AWS credentials for the dev account, and the `terraform` CLI on
`PATH` (only to read the bucket name; pass `--bucket` to skip it).

## Result

**97.0% — 65 of 67 expected findings, across 38 positive cases and 2 clean
controls. 23 seconds.** Run 2026-09-10 against checkov 3.3.16 and tfsec
v1.28.14, as packaged in `layers/`.

| category | recall |
|---|---|
| network-exposure | 19/19 |
| missing-encryption | 21/21 |
| logging-monitoring | 10/10 |
| unpinned-modules | 2/2 |
| iam-over-permissioning | 10/11 |
| hardcoded-secrets | 3/4 |
| **by source** | checkov 38/40 · tfsec 27/27 |

Both clean controls raised nothing.

## Mapping coverage

The same run also reports what fraction of findings have a candidate control
in `rule_mappings.json` — spec §7.1's second half. Read from the file rather
than from a `mapping-agent` run: it is a property of the corpus, costs
nothing, and is deterministic.

| | coverage |
|---|---|
| labelled pairs that fired | **44/61 — 72%** |
| all distinct rules fired | **48/123 — 39%** |

Two numbers because they answer different questions. The first is comparable
with detection recall above. The second is the honest one for a real PR: the
labels are a deliberate *minimum*, so 40 cases written to catch 67 specific
pairs actually raise 123 distinct rules, and a reviewer's queue reflects the
123. Most of the long tail is rules no case was written for —
`aws-rds-enable-performance-insights`, `aws-eks-enable-control-plane-logging`,
RDS backup retention — which are real findings with no control in the three
frameworks loaded.

It measures whether a finding *can* be mapped, not whether the agent picks
well among the candidates. That would need a labelled expected control per
case and a live run, and is not measured.

### The two misses are real, and each names a specific gap

**`CKV_AWS_60` on `iam-role-assumable-by-anyone`.** The check
(`IAMRoleAllowsPublicAssume.py`) only ever inspects `statement['Principal']['AWS']`.
A trust policy with the bare `Principal = "*"` — the fully anonymous form,
the more dangerous of the two — is never examined. The sibling case
`iam-role-assumable-by-any-aws-principal` uses `Principal = { AWS = "*" }` and
hits, which is what isolates the blind spot to the bare form.

**`CKV_SECRET_6` on `rds-literal-password`.** `CKV_SECRET_*` belongs to
checkov's `secrets` framework, and the scanner runs `--framework terraform`
only. This is the §2 goal "hardcoded secrets" measured rather than assumed:
a literal master password in an `aws_db_instance` is not detected. Kept as a
positive on purpose — §8.2 item 4 is where it gets fixed, and this is the
number that should move when it does.

### A tfsec coverage gap that is labelled, not counted

tfsec's `aws-ec2-no-public-ip` fires on `aws_launch_configuration` and on
nothing else. `aws_instance` with `associate_public_ip_address = true` and
`aws_launch_template` with the same in `network_interfaces` are both
tfsec-blind. The three `*-public-ip` cases pin this down; checkov's
`CKV_AWS_88` covers all three resource types, so the pipeline as a whole
still catches it. The two modern-form cases are labelled for checkov only,
with the tfsec gap recorded in their `note`.

## How the labels were produced, and what happened to them

This section exists so the number above is not circular.

**checkov labels were verified a priori** against the vendored source in
`layers/checkov/python/checkov/` — every `CKV_*` id in every `expected.json`
appears as a check id in the exact version deployed. (Rule ids live in
`.py`, `.yaml` **and** `.json` graph checks; an index that skips the JSON
files misses the S3 rules entirely.)

**tfsec labels could not be verified against source** — no binary runs here.
Twelve of the ids were observed firing in earlier live scans; the rest were
labelled from documentation. The short-name component of every tfsec id used
here (`no-public-ip`, `enable-bucket-encryption`, …) was confirmed embedded in
the deployed binary, which proves the rule exists but not which resources it
covers.

**Corrections log.** The first run scored 92.3%. Each miss was then classified
as either a label error (mine — corrected, listed here) or a scanner gap
(kept, reported above). Nothing was relabelled to match output without a
source-level reason.

| run | case | was | now | why |
|---|---|---|---|---|
| 1→2 | `iam-credentials-exposure` | `CKV_AWS_107` | `CKV_AWS_287` | 107 is the `aws_iam_policy_document` data-source variant; the resource check is 287, and it had fired |
| 1→2 | `iam-privilege-escalation` | `CKV_AWS_110` | `CKV_AWS_286` | same split; 286 had fired |
| 1→2 | `ec2-public-ip` | + `tfsec aws-ec2-no-public-ip` | checkov only | tfsec raised nothing on `aws_instance`; see the coverage gap above |
| 1→2 | `clean-sg-restricted` | orphaned SG | attached to an ENI | `CKV2_AWS_5` (SG attached to nothing) is a fair finding, so the control was not clean |
| 1→2 | *(added)* `iam-role-assumable-by-any-aws-principal` | — | `CKV_AWS_60` | isolates the bare-`"*"` blind spot to that form |
| 2→3 | *(added)* `launch-configuration-public-ip` | — | `tfsec aws-ec2-no-public-ip` | tests where the tfsec rule does apply; it fired |
| 3→4 | `launch-template-public-ip` | `tfsec aws-ec2-no-public-ip` | `CKV_AWS_88` | tfsec raised nothing on the launch template either; the rule is launch-configuration only |

## What recall means here, and what it does not

Recall is per expected `(source, rule_id)` pair: hit if that pair fired on
that case's file at least once. The labels are a **minimum** — a bare S3
bucket raises a dozen rules, and its case expects only the encryption pair.
Extra findings are reported but never counted against recall, because they
are correct.

The two clean controls are the only precision signal. Anything they raise
is reported as a false positive. Getting a truly zero-finding case is
harder than it sounds — an unattached security group is a finding — which is
its own small lesson about what "clean" means to these tools.

Not measured: mapping recall (§7.1's second half, needs labelled control
mappings), remediation safety (§7.2), fix acceptance (§7.3).

## Adding a case

```
cases/<name>/main.tf          # one clear injected vulnerability, self-contained
cases/<name>/expected.json    # {description, category, expected: [{source, rule_id}], note?}
```

Keep `main.tf` minimal and valid — `terraform fmt -check -recursive cases/`
must pass, which also proves every case parses. Verify a checkov id against
`layers/checkov/python/checkov/` before labelling it. If a tfsec id is a
guess, say so in `note` and let the run decide.

Runs cost one scanner invocation regardless of case count: everything is
uploaded under one prefix and tfsec/checkov treat each subdirectory as its own
module. The prefix is deleted afterwards unless `--keep` is passed.
