import { useState } from 'react'
import { useAuth } from '../auth/AuthProvider'
import type { ReviewAction } from '../types/finding'

interface ReviewActionsProps {
  disabled?: boolean
  /** Why the actions are disabled, shown above the buttons. Without this a
   *  reviewer just sees dead controls and reasonably reads it as a bug. */
  disabledReason?: string
  /** Keep Reject live while approve and edit are disabled. Set when the block
   *  is an unmet fix-chain prerequisite: refusing a fix is always coherent and
   *  is the reviewer's only way out of a chain that cannot be assembled, so
   *  disabling it would trap them. Notes stay editable for the same reason --
   *  a rejection is exactly the decision that wants explaining. */
  allowReject?: boolean
  /** The fix's corrected file, to prefill the edit textarea with. The
   *  reviewer edits the file, not the diff: the API computes the diff against
   *  the fix's base, so what they submit is always something that applies.
   *  Approve-with-edits is hidden entirely when this is absent -- there's
   *  nothing to edit. */
  currentContent?: string
  onSubmit: (payload: { action: ReviewAction; notes: string; edited_content?: string }) => Promise<void>
}

export function ReviewActions({
  disabled,
  disabledReason,
  allowReject,
  currentContent,
  onSubmit,
}: ReviewActionsProps) {
  const { actor } = useAuth()
  const [notes, setNotes] = useState('')
  const [editing, setEditing] = useState(false)
  const [editedContent, setEditedContent] = useState(currentContent ?? '')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  async function handleAction(action: ReviewAction, editedContentValue?: string) {
    setSubmitting(true)
    setError(null)
    setSuccess(null)

    try {
      await onSubmit({ action, notes: notes.trim(), edited_content: editedContentValue })
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
    setEditedContent(currentContent ?? '')
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
          disabled={(disabled && !allowReject) || submitting}
        />
      </div>

      {editing && (
        <div className="form-field">
          <label htmlFor="edited-content">Edited file</label>
          <textarea
            id="edited-content"
            className="review-actions__diff-editor"
            value={editedContent}
            onChange={(e) => setEditedContent(e.target.value)}
            rows={24}
            spellCheck={false}
            disabled={submitting}
          />
          <p className="muted">
            This is the whole corrected file. The diff is computed from it on save, and
            saving clears the self-check: this version has not been run through the scanner.
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
            {currentContent !== undefined && (
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
              disabled={(disabled && !allowReject) || submitting}
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
              disabled={submitting || editedContent.trim() === '' || editedContent === currentContent}
              onClick={() => handleAction('edited', editedContent)}
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
