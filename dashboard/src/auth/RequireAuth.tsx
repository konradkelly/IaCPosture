import { useEffect } from 'react'
import type { ReactNode } from 'react'
import { useAuth } from './AuthProvider'
import { authConfigured } from './config'

export function RequireAuth({ children }: { children: ReactNode }) {
  const { token, login } = useAuth()

  useEffect(() => {
    if (!token && authConfigured()) login()
  }, [token, login])

  if (!authConfigured()) {
    return (
      <div className="alert alert--warn">
        <strong>Auth not configured.</strong> Set <code>VITE_COGNITO_DOMAIN</code> and{' '}
        <code>VITE_COGNITO_CLIENT_ID</code> in <code>.env</code> (see <code>terraform output</code>
        ).
      </div>
    )
  }

  if (!token) {
    return <p className="muted">Redirecting to sign in…</p>
  }

  return <>{children}</>
}
