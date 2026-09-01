# Control corpus

Reference text `mapping-agent` cites when it maps a raw finding to a control
(spec §4.4 step 4, §6). Lives in S3 under `corpus/` on the artifacts bucket;
`upload.sh` syncs this directory there.

## Structure

- `frameworks/*.json` — one file per framework. Each control has a
  `control_id`, `title`, and short `text` description.
- `rule_mappings.json` — maps a scanner finding's `(source, rule_id)` to
  candidate controls. `mapping-agent` looks a finding up here first and only
  asks the LLM to pick/cite/explain among those candidates, rather than
  letting it freely guess a control_id from scratch — this is what keeps
  citations grounded instead of hallucinated.

## On the control text

The `text` field in each framework file is an **original summary I wrote**,
not a verbatim quote from the official CIS or OWASP documents — CIS Benchmark
text in particular isn't freely redistributable. Control IDs, titles, and
framework versions were verified against the sources listed in each file's
`source` field; the summaries are accurate to the control's actual meaning
but are our own wording, not a copy of the official text.

## Coverage

Only 9 CIS-AWS-1.4 controls, 4 OWASP-CloudNative items, and 2
OWASP-CICD-Top10 items are included — enough to cover the finding types
`terraform-scanner`'s test fixture actually produces (S3 public access,
encryption, logging; open security-group ingress), plus IaC-relevant items
(secrets storage, module pinning) not yet exercised by the fixture. This is
deliberately partial, not the full benchmarks: `rule_mappings.json` only maps
rule_ids we've actually observed rather than guessing ahead of evidence, and
a scanner rule with no confident mapping (e.g. pure hygiene checks like
"add a description to this security group rule") is left unmapped rather
than forced onto a control it doesn't really violate. Extend both files as
new rule_ids turn up in real scans.
