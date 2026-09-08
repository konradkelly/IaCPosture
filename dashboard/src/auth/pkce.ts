/**
 * Authorization-code + PKCE against the Cognito Hosted UI, hand-rolled.
 *
 * Amplify would be 200 kB+ and wants to own the app lifecycle; oidc-client-ts
 * turns the flow into a black box for the sake of ~100 lines. crypto.subtle is
 * available over HTTPS and on localhost, which is the only requirement here.
 */

import { COGNITO_CLIENT_ID, COGNITO_DOMAIN } from './config'

const VERIFIER_KEY = 'iacposture.pkce_verifier'
const STATE_KEY = 'iacposture.pkce_state'
const RETURN_TO_KEY = 'iacposture.return_to'

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function randomToken(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

/** Computed rather than configured, so one build serves both the CloudFront
 *  origin and localhost. Must match a callback_url in cognito.tf verbatim. */
export function redirectUri(): string {
  return `${window.location.origin}/auth/callback`
}

export async function beginLogin(): Promise<void> {
  const verifier = randomToken()
  const state = randomToken()

  sessionStorage.setItem(VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)
  sessionStorage.setItem(RETURN_TO_KEY, window.location.pathname + window.location.search)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: COGNITO_CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: 'openid email profile',
    state,
    code_challenge_method: 'S256',
    code_challenge: await codeChallenge(verifier),
  })

  window.location.assign(`https://${COGNITO_DOMAIN}/oauth2/authorize?${params}`)
}

/** Exchanges the callback's code for an ID token. Returns the raw token. */
export async function completeLogin(code: string, state: string | null): Promise<string> {
  const verifier = sessionStorage.getItem(VERIFIER_KEY)
  const expectedState = sessionStorage.getItem(STATE_KEY)
  // Single-use, whether or not the exchange below succeeds.
  sessionStorage.removeItem(VERIFIER_KEY)
  sessionStorage.removeItem(STATE_KEY)

  if (!verifier) {
    throw new Error('No PKCE verifier in this session — start the sign-in again.')
  }
  // CSRF protection: a code delivered with a state we did not issue is not ours.
  if (!expectedState || state !== expectedState) {
    throw new Error('OAuth state mismatch — refusing to exchange this code.')
  }

  const response = await fetch(`https://${COGNITO_DOMAIN}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: COGNITO_CLIENT_ID,
      code,
      redirect_uri: redirectUri(),
      code_verifier: verifier,
    }),
  })

  if (!response.ok) {
    throw new Error(`Token exchange failed (${response.status}).`)
  }

  const tokens = (await response.json()) as { id_token?: string }
  if (!tokens.id_token) {
    throw new Error('Token response carried no id_token.')
  }
  // The ID token, not the access token: the authorizer's audience check matches
  // aud = client_id, which only the ID token carries, and review-api reads the
  // email claim from it for the audit trail.
  return tokens.id_token
}

export function consumeReturnTo(): string {
  const path = sessionStorage.getItem(RETURN_TO_KEY)
  sessionStorage.removeItem(RETURN_TO_KEY)
  return path && path !== '/auth/callback' ? path : '/'
}

export function hostedLogoutUrl(): string {
  const params = new URLSearchParams({
    client_id: COGNITO_CLIENT_ID,
    logout_uri: window.location.origin,
  })
  return `https://${COGNITO_DOMAIN}/logout?${params}`
}
