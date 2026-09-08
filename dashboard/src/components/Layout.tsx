import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="layout">
      <header className="header">
        <Link to="/" className="header__brand">
          <span className="header__logo">IaCPosture</span>
          <span className="header__tagline">Review dashboard</span>
        </Link>
      </header>
      <main className="main">{children}</main>
      <footer className="footer">
        <p>
          Agent proposes, human disposes — every decision is audited. v1 has no auth; keep the API
          URL private until Cognito lands in v1.1.
        </p>
      </footer>
    </div>
  )
}
