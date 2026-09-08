import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { beginLogin, hostedLogoutUrl } from './pkce'
import { actorFromToken, clearToken, readToken, storeToken } from './token'

interface AuthValue {
  token: string | null
  actor: string | null
  login: () => void
  logout: () => void
  onAuthenticated: (token: string) => void
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => readToken())

  const onAuthenticated = useCallback((next: string) => {
    storeToken(next)
    setToken(next)
  }, [])

  const logout = useCallback(() => {
    clearToken()
    setToken(null)
    // Also end the Hosted UI session -- otherwise the next login silently
    // re-authenticates and "sign out" looks like it did nothing.
    window.location.assign(hostedLogoutUrl())
  }, [])

  const value = useMemo<AuthValue>(
    () => ({
      token,
      actor: token ? actorFromToken(token) : null,
      login: () => void beginLogin(),
      logout,
      onAuthenticated,
    }),
    [token, logout, onAuthenticated],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}
