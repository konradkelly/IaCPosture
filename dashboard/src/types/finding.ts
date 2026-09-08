/** Mirrors spec §5 FindingRecord + ReviewEvent shapes from review-api. */

export type FindingStatus =
  | 'raw'
  | 'mapped'
  | 'fix-proposed'
  | 'needs-human-only'
  | 'resolved'

export type ReviewAction = 'approved' | 'edited' | 'rejected'

export interface ControlMapping {
  framework: string
  control_id: string
  control_text_ref?: string
  citation_span?: string
  rationale?: string
}

export interface ProposedFix {
  diff?: string
  rationale?: string
  self_check_passed?: boolean
  self_check_new_findings?: string[]
}

export interface Finding {
  pk: string
  sk: string
  finding_id: string
  iac_type?: string
  source: string
  rule_id: string
  file: string
  line_range?: [number | null, number | null]
  severity?: string
  control_mappings?: ControlMapping[]
  status: FindingStatus
  proposed_fix?: ProposedFix | null
  created_at?: string
  updated_at?: string
}

export interface ReviewEvent {
  pk: string
  sk: string
  finding_id: string
  pr_id?: string
  actor: string
  action: ReviewAction
  notes?: string
  created_at: string
}

export interface FindingsListResponse {
  pr_id: string
  count: number
  findings: Finding[]
}

export interface EventsListResponse {
  finding_id: string
  count: number
  events: ReviewEvent[]
}

export interface ReviewResponse {
  finding_id: string
  action: ReviewAction
  status: string | null
  recorded_at: string
}

export interface ApiError {
  error: string
}
