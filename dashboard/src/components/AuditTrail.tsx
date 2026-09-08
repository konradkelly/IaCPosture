import type { ReviewEvent } from '../types/finding'

interface AuditTrailProps {
  events: ReviewEvent[]
  loading?: boolean
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function AuditTrail({ events, loading }: AuditTrailProps) {
  if (loading) {
    return <p className="muted">Loading audit trail…</p>
  }

  if (events.length === 0) {
    return <p className="muted">No review decisions recorded yet.</p>
  }

  const sorted = [...events].sort((a, b) => b.created_at.localeCompare(a.created_at))

  return (
    <ul className="audit-trail">
      {sorted.map((event) => (
        <li key={event.sk} className="audit-trail__item">
          <div className="audit-trail__header">
            <span className={`audit-trail__action audit-trail__action--${event.action}`}>
              {event.action}
            </span>
            <span className="audit-trail__actor">{event.actor}</span>
            <time className="audit-trail__time" dateTime={event.created_at}>
              {formatTimestamp(event.created_at)}
            </time>
          </div>
          {event.notes && <p className="audit-trail__notes">{event.notes}</p>}
        </li>
      ))}
    </ul>
  )
}
