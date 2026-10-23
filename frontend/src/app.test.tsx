import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, qs } from './api'
import Overview from './pages/Overview'
import { Confidence, Pagination, SevBadge, ToastProvider } from './ui'
import { pivotQuery } from './components'

afterEach(() => vi.restoreAllMocks())

function mockFetch(routes: Record<string, any>, status = 200) {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const path = Object.keys(routes).find((r) => url.includes(r))
    return new Response(JSON.stringify(path ? routes[path] : {}), { status: path ? status : 404 })
  }))
}

describe('api client', () => {
  it('builds query strings and drops empty values', () => {
    expect(qs({ a: 1, b: '', c: undefined, d: 'x y' })).toBe('?a=1&d=x+y')
  })
  it('surfaces backend error detail', async () => {
    mockFetch({ '/api/x': { detail: 'Invalid query: nope' } }, 400)
    await expect(api('/api/x')).rejects.toThrow('Invalid query: nope')
  })
  it('formats validation error arrays', async () => {
    mockFetch({ '/api/x': { detail: [{ loc: ['body', 'title'], msg: 'too short' }] } }, 422)
    await expect(api('/api/x')).rejects.toThrow('title: too short')
  })
  it('reports an unreachable backend with a useful message', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('network') }))
    const e = await api('/api/x').catch((x) => x)
    expect(e).toBeInstanceOf(ApiError)
    expect(e.status).toBe(0)
    expect(e.message).toMatch(/Cannot reach the HuntForge backend/)
  })
})

describe('components', () => {
  it('renders severity and confidence', () => {
    render(<><SevBadge sev="critical" /><Confidence value={0.85} /></>)
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText(/High 85%/)).toBeInTheDocument()
  })
  it('paginates', () => {
    const onPage = vi.fn()
    render(<Pagination page={1} pages={3} total={120} onPage={onPage} />)
    expect(screen.getByText('120 results')).toBeInTheDocument()
    expect(screen.getByText('Previous')).toBeDisabled()
    screen.getByText('Next').click()
    expect(onPage).toHaveBeenCalledWith(2)
  })
  it('escapes quotes when building pivot queries', () => {
    expect(pivotQuery('username', 'a"b')).toBe('username = "a\\"b"')
  })
})

describe('Overview page', () => {
  it('shows an empty state with sample-data option when no data exists', async () => {
    mockFetch({ '/api/overview': { has_data: false, totals: { events_ingested: 0 } } })
    render(<MemoryRouter><ToastProvider><Overview /></ToastProvider></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('No log data yet')).toBeInTheDocument())
    expect(screen.getByText(/Load synthetic sample dataset/)).toBeInTheDocument()
  })
  it('shows a recoverable error when the backend fails', async () => {
    mockFetch({ '/api/overview': { detail: 'Internal server error' } }, 500)
    render(<MemoryRouter><ToastProvider><Overview /></ToastProvider></MemoryRouter>)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Internal server error'))
    expect(screen.getByText('Retry')).toBeInTheDocument()
  })
})
