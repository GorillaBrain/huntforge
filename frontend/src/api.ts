export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

const BASE = ((import.meta.env.VITE_API_URL as string | undefined) ?? '').replace(/\/$/, '')

export const apiBase = BASE || '(same origin /api)'

type Opts = { method?: string; body?: unknown; params?: Record<string, any>; form?: FormData }

export function qs(params?: Record<string, any>): string {
  if (!params) return ''
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  const s = u.toString()
  return s ? `?${s}` : ''
}

export function apiUrl(path: string, params?: Record<string, any>) {
  return `${BASE}${path}${qs(params)}`
}

function formatDetail(d: any): string {
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((x) => `${(x.loc || []).slice(1).join('.')}: ${x.msg}`).join('; ')
  return 'Request failed'
}

export async function api<T = any>(path: string, opts: Opts = {}): Promise<T> {
  let res: Response
  try {
    res = await fetch(apiUrl(path, opts.params), {
      method: opts.method ?? 'GET',
      headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: opts.form ?? (opts.body !== undefined ? JSON.stringify(opts.body) : undefined),
    })
  } catch {
    throw new ApiError(`Cannot reach the HuntForge backend (${apiBase}). Check that the API is running and VITE_API_URL is correct.`, 0)
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: any = null
  try { data = text ? JSON.parse(text) : null } catch { /* non-JSON */ }
  if (!res.ok) throw new ApiError(data ? formatDetail(data.detail) : `HTTP ${res.status}`, res.status)
  return data as T
}
