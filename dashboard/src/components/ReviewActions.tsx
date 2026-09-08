import { useState } from 'react'
import type { ReviewAction } from '../types/finding'

interface ReviewActionsProps {
  disabled?: boolean
  onSubmit: (payload: { action: ReviewAction; actor: string; notes: string }) => Promise<void>
}

export function ReviewActions({ disabled, onSubmit }: ReviewActionsProps) {
  const [actor, setActor] = useState('')
  const [notes, setNotes] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  async function handleAction(action: ReviewAction) {
    if (!actor.trim()) {
      setError('Reviewer name is required for audit trail.')
      return
    }

    setSubmitting(true)
    setError(null)
    setSuccess(null)

    try {
      await onSubmit({ action, actor: actor.trim(), notes: notes.trim() })
      setSuccess(
        action === 'rejected'
          ? 'Rejection recorded. Finding remains open.'
          : 'Decision recorded. Finding marked resolved.',
      )
      setNotes('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit review')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="review-actions">
      <h2>Review decision</h2>
      <p className="muted">
        The agent proposes; you dispose. Every decision is logged as an immutable audit event.
      </p>

      <div className="form-field">
        <label htmlFor="reviewer-actor">Your name</label>
        <input
          id="reviewer-actor"
          type="text"
          value={actor}
          onChange={(e) => setActor(e.target.value)}
          placeholder="e.g. konrad"
          disabled={disabled || submitting}
        />
      </div>

      <div className="form-field">
        <label htmlFor="reviewer-notes">Notes (optional)</label>
        <textarea
          id="reviewer-notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Why you approved, edited, or rejected this fix…"
          rows={3}
          disabled={disabled || submitting}
        />
      </div>

      <div className="review-actions__buttons">
        <button
          type="button"
          className="btn btn--approve"
          disabled={disabled || submitting}
          onClick={() => handleAction('approved')}
        >
          Approve
        </button>
        <button
          type="button"
          className="btn btn--edit"
          disabled={disabled || submitting}
          onClick={() => handleAction('edited')}
        >
          Approve with edits
        </button>
        <button
          type="button"
          className="btn btn--reject"
          disabled={disabled || submitting}
          onClick={() => handleAction('rejected')}
        >
          Reject fix
        </button>
      </div>

      {error && <p className="alert alert--error">{error}</p>}
      {success && <p className="alert alert--success">{success}</p>}
    </section>
  )
}
