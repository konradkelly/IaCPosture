/**
 * Token storage, kept outside React so the API client can read it without
 * being handed it through props.
 *
 * sessionStorage rather than localStorage: cleared when the tab closes and not
 * shared across tabs. Memory-only would be stricter, but it forces a full
 * redirect through the Hosted UI on every refresh, which is a bad trade for a
 * single-reviewer tool. Only the ID token is kept -- no refresh token is
 * requested, so an expired session means signing in again rather than silent
 * renewal machinery.
 */

const TOKEN_KEY = 'iacposture.id_token'

interface IdTokenClaims {
  exp?: number
  email?: string
  'cognito:username'?: string
  sub?: string
}

export function decodeClaims(token: string): IdTokenClaims | null {
  const payload = token.split('.')[1]
  if (!payload) return null
  try {
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as IdTokenClaims
  } catch {
    return null
  }
}

export function storeToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY)
}

/**
 * The stored token, or null if it is missing, unreadable, or expired.
 *
 * The expiry check is a UX shortcut, not a security control -- it avoids a
 * round trip that would 401 anyway. API Gateway is what actually validates
 * this token, and it does not care what the browser believed.
 */
export function readToken(): string | null {
  const token = sessionStorage.getItem(TOKEN_KEY)
  if (!token) return null

  const claims = decodeClaims(token)
  if (!claims?.exp || claims.exp * 1000 <= Date.now()) {
    clearToken()
    return null
  }
  return token
}

/** Display only. The actor recorded in the audit trail is derived server-side
 *  from the same token, so this cannot drift from what gets written. */
export function actorFromToken(token: string): string | null {
  const claims = decodeClaims(token)
  return claims?.email ?? claims?.['cognito:username'] ?? claims?.sub ?? null
}
