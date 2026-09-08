import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ApiClientError,
  getFinding,
  listEvents,
  postReview,
} from '../api/client'
import { AuditTrail } from '../components/AuditTrail'
import { ControlMapping } from '../components/ControlMapping'
import { DiffViewer } from '../components/DiffViewer'
import { ReviewActions } from '../components/ReviewActions'
import { SelfCheckBadge } from '../components/SelfCheckBadge'
import { StatusBadge } from '../components/StatusBadge'
import type { Finding, ReviewEvent } from '../types/finding'

export function FindingDetailPage() {
  const { prId, findingId } = useParams<{ prId: string; findingId: string }>()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [events, setEvents] = useState<ReviewEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [eventsLoading, setEventsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadFinding = useCallback(async () => {
    if (!prId || !findingId) return
    setLoading(true)
    setError(null)
    try {
      setFinding(await getFinding(prId, findingId))
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : 'Failed to load finding')
    } finally {
      setLoading(false)
    }
  }, [prId, findingId])

  const loadEvents = useCallback(async () => {
    if (!prId || !findingId) return
    setEventsLoading(true)
    try {
      const data = await listEvents(prId, findingId)
      setEvents(data.events)
    } catch {
      setEvents([])
    } finally {
      setEventsLoading(false)
    }
  }, [prId, findingId])

  useEffect(() => {
    loadFinding()
    loadEvents()
  }, [loadFinding, loadEvents])

  async function handleReview(payload: {
    action: 'approved' | 'edited' | 'rejected'
    actor: string
    notes: string
  }) {
    if (!prId || !findingId) return
    await postReview(prId, findingId, payload)
    await Promise.all([loadFinding(), loadEvents()])
  }

  if (!prId || !findingId) {
    return <p className="alert alert--error">Missing PR or finding ID.</p>
  }

  if (loading) {
    return <p className="muted">Loading finding…</p>
  }

  if (error || !finding) {
    return (
      <div className="page">
        <p className="alert alert--error">{error ?? 'Finding not found'}</p>
        <Link to={`/prs/${encodeURIComponent(prId)}`}>Back to findings list</Link>
      </div>
    )
  }

  const canReview = finding.status !== 'resolved'
  const showDiff =
    finding.proposed_fix?.diff &&
    (finding.status === 'fix-proposed' || finding.status === 'resolved')

  return (
    <div className="page finding-page">
      <nav className="breadcrumb">
        <Link to="/">Home</Link>
        <span aria-hidden="true"> / </span>
        <Link to={`/prs/${encodeURIComponent(prId)}`}>{prId}</Link>
        <span aria-hidden="true"> / </span>
        <span>{finding.finding_id}</span>
      </nav>

      <div className="finding-header">
        <div>
          <h1>
            <code>{finding.rule_id}</code>
          </h1>
          <p className="finding-meta">
            <span>{finding.source}</span>
            <span>·</span>
            <code>{finding.file}</code>
            {finding.line_range?.[0] != null && (
              <>
                <span>·</span>
                <span>
                  line{finding.line_range[0]}
                  {finding.line_range[1] != null && finding.line_range[1] !== finding.line_range[0]
                    ? `–${finding.line_range[1]}`
                    : ''}
                </span>
              </>
            )}
            {finding.severity && (
              <>
                <span>·</span>
                <span>{finding.severity}</span>
              </>
            )}
          </p>
        </div>
        <div className="finding-header__badges">
          <StatusBadge status={finding.status} />
          <SelfCheckBadge proposedFix={finding.proposed_fix} />
        </div>
      </div>

      <section className="panel">
        <h2>Control mapping</h2>
        <ControlMapping mappings={finding.control_mappings} />
      </section>

      {finding.proposed_fix?.rationale && (
        <section className="panel">
          <h2>Remediation rationale</h2>
          <p>{finding.proposed_fix.rationale}</p>
          {finding.proposed_fix.self_check_new_findings &&
            finding.proposed_fix.self_check_new_findings.length > 0 && (
              <div className="alert alert--warn">
                <strong>New findings from self-check:</strong>
                <ul>
                  {finding.proposed_fix.self_check_new_findings.map((id) => (
                    <li key={id}>
                      <code>{id}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}
        </section>
      )}

      {finding.status === 'needs-human-only' && !showDiff && (
        <section className="panel">
          <h2>Proposed fix</h2>
          <div className="alert alert--warn">
            Self-check did not pass — no diff is attached. Review the rationale and address this
            finding manually.
          </div>
        </section>
      )}

      {showDiff && (
        <section className="panel">
          <h2>Proposed diff</h2>
          <DiffViewer diff={finding.proposed_fix?.diff} fileName={finding.file} />
        </section>
      )}

      {canReview && (
        <ReviewActions
          disabled={finding.status === 'raw' || finding.status === 'mapped'}
          onSubmit={handleReview}
        />
      )}

      {finding.status === 'raw' || finding.status === 'mapped' ? (
        <p className="muted review-hint">
          Review actions unlock once remediation completes (status <code>fix-proposed</code> or{' '}
          <code>needs-human-only</code>).
        </p>
      ) : null}

      {finding.status === 'resolved' && (
        <p className="alert alert--success">This finding has been resolved.</p>
      )}

      <section className="panel">
        <h2>Audit trail</h2>
        <AuditTrail events={events} loading={eventsLoading} />
      </section>
    </div>
  )
}
