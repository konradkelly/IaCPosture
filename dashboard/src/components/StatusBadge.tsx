import type { FindingStatus } from '../types/finding'

const LABELS: Record<FindingStatus, string> = {
  raw: 'Raw',
  mapped: 'Mapped',
  'fix-proposed': 'Fix proposed',
  'needs-human-only': 'Needs human',
  resolved: 'Resolved',
}

interface StatusBadgeProps {
  status: FindingStatus
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return <span className={`badge badge--${status}`}>{LABELS[status] ?? status}</span>
}
