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
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusBadge } from '../components/StatusBadge'
import type { Finding, ReviewEvent } from '../types/finding'

export function FindingDetailPage() {
  const { prId, findingId } = useParams<{ prId: string; findingId: string }>()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [events, setEvents] = useState<ReviewEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [eventsLoading, setEventsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAgentDiff, setShowAgentDiff] = useState(false)

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
    notes: string
    edited_diff?: string
  }) {
    if (!prId || !findingId) return
    await postReview(prId, findingId, payload)
    setShowAgentDiff(false)
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
  const awaitingRemediation = finding.status === 'raw' || finding.status === 'mapped'
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
          </p>
        </div>
        <div className="finding-header__badges">
          <SeverityBadge severity={finding.severity} />
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

          {finding.proposed_fix.suppression_attempt &&
            finding.proposed_fix.suppression_attempt.length > 0 && (
              <div className="alert alert--error">
                <p>
                  <strong>This fix tried to silence the scanner, not fix the finding.</strong> It
                  was rejected before being scanned — a suppression comment would clear the rule
                  without changing anything, and would otherwise have passed the self-check.
                </p>
                <ul>
                  {finding.proposed_fix.suppression_attempt.map((line) => (
                    <li key={line}>
                      <code>{line}</code>
                    </li>
                  ))}
                </ul>
                <p>
                  If the flagged configuration really is intentional, that's a human decision to
                  record here — not something the agent may assert for you.
                </p>
              </div>
            )}

          {finding.proposed_fix.dropped_resources &&
            finding.proposed_fix.dropped_resources.length > 0 && (
              <div className="alert alert--warn">
                <p>
                  <strong>This fix deletes infrastructure rather than tightening it.</strong>{' '}
                  Removing a resource always satisfies the scanner, because the thing that raised
                  the finding is gone — but it may remove something the running system depends on.
                  The scanner cannot tell the difference.
                </p>
                <ul>
                  {finding.proposed_fix.dropped_resources.map((r) => (
                    <li key={r}>
                      <code>{r}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}

          {finding.proposed_fix.assumptions &&
            finding.proposed_fix.assumptions.length > 0 && (
              <div className="alert alert--warn">
                <p>
                  <strong>This fix rests on facts the agent could not check.</strong> It saw only
                  this one file — not the rest of the repository, nor the running system. Verify
                  each of these before approving:
                </p>
                <ul>
                  {finding.proposed_fix.assumptions.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </div>
            )}

          {finding.proposed_fix.self_check_passed === false &&
            !finding.proposed_fix.suppression_attempt?.length &&
            !finding.proposed_fix.dropped_resources?.length &&
            !finding.proposed_fix.assumptions?.length && (
            <div className="alert alert--warn">
              {/* cleared distinguishes two different failures: the fix missed
                  the original finding, or it cleared the original but
                  introduced new ones. The second is often one edit away from
                  passing; the first is not. Reporting both as a single
                  generic "self-check failed" understates the second case. */}
              {finding.proposed_fix.cleared === false ? (
                <p>
                  <strong>The rescan still reports this finding</strong> — the fix did not clear it.
                  Do not apply as-is.
                </p>
              ) : finding.proposed_fix.cleared === true ? (
                <p>
                  <strong>The rescan confirmed this finding cleared</strong>, but the fix introduced
                  new findings. Do not apply as-is without addressing them.
                </p>
              ) : (
                <p>The scanner did not confirm this fix. Do not apply as-is.</p>
              )}
              {finding.proposed_fix.self_check_new_findings &&
                finding.proposed_fix.self_check_new_findings.length > 0 && (
                  <>
                    <strong>New findings from self-check:</strong>
                    <ul>
                      {finding.proposed_fix.self_check_new_findings.map((id) => (
                        <li key={id}>
                          <code>{id}</code>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
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
          <div className="panel__header">
            <h2>Proposed diff</h2>
            {finding.proposed_fix?.agent_diff && (
              <button
                type="button"
                className="btn btn--secondary btn--small"
                onClick={() => setShowAgentDiff((shown) => !shown)}
              >
                {showAgentDiff ? "Show reviewer's edit" : "Show agent's original"}
              </button>
            )}
          </div>
          <DiffViewer
            diff={
              showAgentDiff && finding.proposed_fix?.agent_diff
                ? finding.proposed_fix.agent_diff
                : finding.proposed_fix?.diff
            }
            fileName={finding.file}
          />
        </section>
      )}

      {canReview && (
        <ReviewActions
          disabled={awaitingRemediation}
          disabledReason={
            awaitingRemediation
              ? 'Remediation has not run for this finding yet, so there is no proposed fix to accept or refuse. Review unlocks at status fix-proposed or needs-human-only.'
              : undefined
          }
          currentDiff={finding.proposed_fix?.diff}
          onSubmit={handleReview}
        />
      )}

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
