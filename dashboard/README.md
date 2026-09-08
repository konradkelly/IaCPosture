# IaCPosture Review Dashboard

React + Vite + TypeScript frontend for human review of scan findings and proposed fixes.

The dashboard talks to the `review-api` Lambda via API Gateway HTTP API. It does not call the scanner, mapping, or remediation Lambdas directly.

## Setup

```bash
cd dashboard
npm install
cp .env.example .env
# Edit .env — set VITE_API_BASE_URL to your deployed endpoint:
#   terraform output -raw review_api_endpoint
npm run dev
```

Open http://localhost:5173, enter a PR ID (e.g. `manual-test-1`), and review findings.

## API routes consumed

| Method | Path | Use |
|--------|------|-----|
| GET | `/prs/{pr_id}/findings` | List all findings for a PR |
| GET | `/prs/{pr_id}/findings/{finding_id}` | Finding detail + proposed diff |
| GET | `/prs/{pr_id}/findings/{finding_id}/events` | Audit trail |
| POST | `/prs/{pr_id}/findings/{finding_id}/review` | Approve / edit / reject |

## Build for static hosting

```bash
npm run build
```

Output goes to `dist/` — ready for S3 + CloudFront when infra is added.

## Security note

v1 has **no authentication**. The API Gateway endpoint is unauthenticated per spec (Cognito deferred to v1.1). Keep the invoke URL private during development. CORS is configured via `dashboard_allowed_origins` in Terraform.

## Project structure

```
src/
├── api/client.ts          # Typed fetch wrapper
├── types/finding.ts       # FindingRecord + ReviewEvent types
├── components/            # UI pieces (table, diff, review form, audit)
└── pages/                 # Home, PR list, finding detail
```
