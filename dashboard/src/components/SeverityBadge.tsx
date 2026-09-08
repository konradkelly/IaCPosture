/** Severity is what drives triage order, so it gets the same badge treatment
 *  as status rather than plain text. Scanners disagree on casing and on which
 *  levels they emit -- checkov often reports nothing at all, which arrives as
 *  UNKNOWN rather than being hidden, since "we don't know how bad this is" is
 *  itself worth seeing. */

interface SeverityBadgeProps {
  severity?: string
}

const KNOWN = ['critical', 'high', 'medium', 'low', 'unknown'] as const

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  if (!severity) {
    return <span className="badge badge--sev-unknown">—</span>
  }

  const normalized = severity.toLowerCase()
  const modifier = (KNOWN as readonly string[]).includes(normalized) ? normalized : 'unknown'

  return <span className={`badge badge--sev-${modifier}`}>{severity}</span>
}
