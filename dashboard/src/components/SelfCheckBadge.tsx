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

  // A parse failure has to be read before cleared/newCount, not alongside them:
  // it sets cleared=false with no new findings, which is the same shape as a
  // fix that was scanned and missed its finding. Falling through would explain
  // an unverified fix as a failed one.
  if (proposedFix.scan_errors?.length) {
    return (
      <span className="badge badge--fail" title="The scanner could not parse the fix, so nothing was verified">
        Fix did not parse
      </span>
    )
  }

  const newCount = proposedFix.self_check_new_findings?.length ?? 0
  const reasons: string[] = []

  // cleared distinguishes the two ways a self-check fails -- a fix that
  // missed the original finding entirely, versus one that cleared it but
  // introduced new findings along the way. A record can be both at once, and
  // guessing from newCount alone (the pre-`cleared` heuristic) silently drops
  // the "original not cleared" half whenever new findings are also present.
  // proposedFix.cleared is undefined on records written before this field
  // existed, in which case that heuristic is the best available fallback.
  if (proposedFix.cleared === false || (proposedFix.cleared === undefined && newCount === 0)) {
    reasons.push('original issue not cleared')
  }
  if (newCount > 0) {
    reasons.push(`${newCount} new finding${newCount === 1 ? '' : 's'} introduced`)
  }

  const detail = reasons.length > 0 ? reasons.join('; ') : 'Original issue not cleared'

  return (
    <span className="badge badge--fail" title={detail}>
      Self-check failed
    </span>
  )
}
