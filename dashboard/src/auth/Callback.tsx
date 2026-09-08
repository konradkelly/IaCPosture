import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from './AuthProvider'
import { completeLogin, consumeReturnTo } from './pkce'

export function Callback() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const { onAuthenticated } = useAuth()
  const [error, setError] = useState<string | null>(null)
  // The verifier is single-use, so React 18 StrictMode double-invoking effects
  // in dev would otherwise turn the second exchange into a spurious failure.
  const exchanged = useRef(false)

  useEffect(() => {
    if (exchanged.current) return
    exchanged.current = true

    const oauthError = params.get('error')
    if (oauthError) {
      setError(`${oauthError}: ${params.get('error_description') ?? 'no description'}`)
      return
    }

    const code = params.get('code')
    if (!code) {
      setError('No authorization code in the callback URL.')
      return
    }

    completeLogin(code, params.get('state'))
      .then((token) => {
        onAuthenticated(token)
        navigate(consumeReturnTo(), { replace: true })
      })
      .catch((err: Error) => setError(err.message))
  }, [params, navigate, onAuthenticated])

  return (
    <div className="page">
      {error ? (
        <p className="alert alert--error">Sign-in failed: {error}</p>
      ) : (
        <p className="muted">Completing sign in…</p>
      )}
    </div>
  )
}
