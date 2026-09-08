import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiConfigured } from '../api/client'

export function HomePage() {
  const navigate = useNavigate()
  const [prId, setPrId] = useState('manual-test-1')

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const trimmed = prId.trim()
    if (trimmed) {
      navigate(`/prs/${encodeURIComponent(trimmed)}`)
    }
  }

  return (
    <div className="page home-page">
      <h1>Security findings review</h1>
      <p className="lead">
        Enter a pull-request ID to load its scan findings, proposed fixes, and audit trail from the
        review API.
      </p>

      {!apiConfigured() && (
        <div className="alert alert--warn">
          <strong>API not configured.</strong> Set <code>VITE_API_BASE_URL</code> in{' '}
          <code>.env</code> to your deployed review-api endpoint (
          <code>terraform output -raw review_api_endpoint</code>).
        </div>
      )}

      <form className="pr-form" onSubmit={handleSubmit}>
        <label htmlFor="pr-id">PR ID</label>
        <div className="pr-form__row">
          <input
            id="pr-id"
            type="text"
            value={prId}
            onChange={(e) => setPrId(e.target.value)}
            placeholder="manual-test-1"
            autoFocus
          />
          <button type="submit" className="btn btn--primary">
            Load findings
          </button>
        </div>
      </form>
    </div>
  )
}
