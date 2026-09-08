import { useState } from 'react'
import { useAuth } from '../auth/AuthProvider'
import type { ReviewAction } from '../types/finding'

interface ReviewActionsProps {
  disabled?: boolean
  /** Why the actions are disabled, shown above the buttons. Without this a
   *  reviewer just sees dead controls and reasonably reads it as a bug. */
  disabledReason?: string
  /** The proposed diff to prefill the edit textarea with. Approve-with-edits
   *  is hidden entirely when this is absent -- there's nothing to edit. */
  currentDiff?: string
  onSubmit: (payload: { action: ReviewAction; notes: string; edited_diff?: string }) => Promise<void>
}

export function ReviewActions({
  disabled,
  disabledReason,
  currentDiff,
  onSubmit,
}: ReviewActionsProps) {
  const { actor } = useAuth()
  const [notes, setNotes] = useState('')
  const [editing, setEditing] = useState(false)
  const [editedDiff, setEditedDiff] = useState(currentDiff ?? '')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  async function handleAction(action: ReviewAction, editedDiffValue?: string) {
    setSubmitting(true)
    setError(null)
    setSuccess(null)

    try {
      await onSubmit({ action, notes: notes.trim(), edited_diff: editedDiffValue })
      setSuccess(
        action === 'rejected'
          ? 'Rejection recorded. Finding remains open.'
          : 'Decision recorded. Finding marked resolved.',
      )
      setNotes('')
      setEditing(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit review')
    } finally {
      setSubmitting(false)
    }
  }

  function startEditing() {
    setEditedDiff(currentDiff ?? '')
    setEditing(true)
  }

  return (
    <section className="review-actions">
      <h2>Review decision</h2>
      <p className="muted">
        The agent proposes; you dispose. Every decision is logged as an immutable audit event,
        attributed to <strong>{actor ?? 'you'}</strong>.
      </p>

      {disabled && disabledReason && (
        <p className="alert alert--info">{disabledReason}</p>
      )}

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

      {editing && (
        <div className="form-field">
          <label htmlFor="edited-diff">Edited diff</label>
          <textarea
            id="edited-diff"
            className="review-actions__diff-editor"
            value={editedDiff}
            onChange={(e) => setEditedDiff(e.target.value)}
            rows={16}
            spellCheck={false}
            disabled={submitting}
          />
          <p className="muted">
            Saving clears the self-check: this diff has not been run through the scanner.
          </p>
        </div>
      )}

      <div className="review-actions__buttons">
        {!editing ? (
          <>
            <button
              type="button"
              className="btn btn--approve"
              disabled={disabled || submitting}
              onClick={() => handleAction('approved')}
            >
              Approve
            </button>
            {currentDiff && (
              <button
                type="button"
                className="btn btn--edit"
                disabled={disabled || submitting}
                onClick={startEditing}
              >
                Approve with edits
              </button>
            )}
            <button
              type="button"
              className="btn btn--reject"
              disabled={disabled || submitting}
              onClick={() => handleAction('rejected')}
            >
              Reject fix
            </button>
          </>
        ) : (
          <>
            <button
              type="button"
              className="btn btn--edit"
              disabled={submitting || editedDiff.trim() === ''}
              onClick={() => handleAction('edited', editedDiff)}
            >
              Save edited fix
            </button>
            <button
              type="button"
              className="btn btn--secondary"
              disabled={submitting}
              onClick={() => setEditing(false)}
            >
              Cancel
            </button>
          </>
        )}
      </div>

      {error && <p className="alert alert--error">{error}</p>}
      {success && <p className="alert alert--success">{success}</p>}
    </section>
  )
}
