import type {
  ApiError,
  EventsListResponse,
  Finding,
  FindingsListResponse,
  ReviewAction,
  ReviewResponse,
} from '../types/finding'

const API_BASE = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

export class ApiClientError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiClientError'
    this.status = status
  }
}

function apiConfigured(): boolean {
  return API_BASE.length > 0
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!apiConfigured()) {
    throw new ApiClientError(
      'VITE_API_BASE_URL is not set. Copy .env.example to .env and point it at your review-api endpoint.',
      0,
    )
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...init?.headers,
    },
  })

  const body = await response.json().catch(() => ({}))

  if (!response.ok) {
    const message = (body as ApiError).error ?? `Request failed (${response.status})`
    throw new ApiClientError(message, response.status)
  }

  return body as T
}

export function listFindings(prId: string): Promise<FindingsListResponse> {
  return request<FindingsListResponse>(`/prs/${encodeURIComponent(prId)}/findings`)
}

export function getFinding(prId: string, findingId: string): Promise<Finding> {
  return request<Finding>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}`,
  )
}

export function listEvents(prId: string, findingId: string): Promise<EventsListResponse> {
  return request<EventsListResponse>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}/events`,
  )
}

export function postReview(
  prId: string,
  findingId: string,
  payload: { action: ReviewAction; actor: string; notes?: string },
): Promise<ReviewResponse> {
  return request<ReviewResponse>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}/review`,
    { method: 'POST', body: JSON.stringify(payload) },
  )
}

export { apiConfigured }
