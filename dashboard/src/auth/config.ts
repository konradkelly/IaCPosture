/**
 * Cognito settings, read at build time like VITE_API_BASE_URL in api/client.ts.
 *
 * `terraform output` prints all three:
 *   cognito_hosted_ui_domain    -> VITE_COGNITO_DOMAIN
 *   cognito_dashboard_client_id -> VITE_COGNITO_CLIENT_ID
 */

export const COGNITO_DOMAIN = import.meta.env.VITE_COGNITO_DOMAIN?.replace(/^https:\/\//, '') ?? ''
export const COGNITO_CLIENT_ID = import.meta.env.VITE_COGNITO_CLIENT_ID ?? ''

export function authConfigured(): boolean {
  return COGNITO_DOMAIN.length > 0 && COGNITO_CLIENT_ID.length > 0
}
