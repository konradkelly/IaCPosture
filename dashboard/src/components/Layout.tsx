import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { actor, logout } = useAuth()

  return (
    <div className="layout">
      <header className="header">
        <Link to="/" className="header__brand">
          <span className="header__logo">IaCPosture</span>
          <span className="header__tagline">Review dashboard</span>
        </Link>
        {actor && (
          <div className="header__account">
            <span className="muted">{actor}</span>
            <button type="button" className="btn btn--secondary" onClick={logout}>
              Sign out
            </button>
          </div>
        )}
      </header>
      <main className="main">{children}</main>
      <footer className="footer">
        <p>Agent proposes, human disposes — every decision is audited and attributed to you.</p>
      </footer>
    </div>
  )
}
