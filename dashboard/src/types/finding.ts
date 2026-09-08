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
  /** The agent's original diff, preserved the first time a reviewer edits the
   *  fix and never overwritten afterwards. Null/absent until an edit happens
   *  -- that's what lets the UI offer an "agent's original / reviewer's edit"
   *  toggle only when there's something to toggle to. */
  agent_diff?: string | null
  rationale?: string
  self_check_passed?: boolean
  self_check_new_findings?: string[]
  /** Whether the rescan confirmed the original finding is gone -- distinct
   *  from self_check_passed, which also requires no new findings. A fix can
   *  clear the original and still fail the self-check by introducing new
   *  ones; without this field that case is indistinguishable from a fix that
   *  missed the original entirely. Absent on records written before this
   *  field existed. */
  cleared?: boolean
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
  /** The diff a reviewer submitted with an "edited" decision, stored verbatim
   *  on the event so the audit record is self-contained even if the finding
   *  itself is edited again later. */
  edited_diff?: string | null
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
