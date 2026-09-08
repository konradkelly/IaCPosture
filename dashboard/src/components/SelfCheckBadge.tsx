import type { ProposedFix } from '../types/finding'

interface SelfCheckBadgeProps {
  proposedFix?: ProposedFix | null
}

export function SelfCheckBadge({ proposedFix }: SelfCheckBadgeProps) {
  if (!proposedFix || proposedFix.self_check_passed === undefined) {
    return <span className="badge badge--muted">No self-check</span>
  }

  if (proposedFix.self_check_passed) {
    return <span className="badge badge--pass">Self-check passed</span>
  }

  const newCount = proposedFix.self_check_new_findings?.length ?? 0
  const detail =
    newCount > 0
      ? `${newCount} new finding${newCount === 1 ? '' : 's'} introduced`
      : 'Original issue not cleared'

  return (
    <span className="badge badge--fail" title={detail}>
      Self-check failed
    </span>
  )
}
