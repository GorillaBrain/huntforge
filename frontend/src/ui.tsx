import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { api } from './api'

/* ---------- data fetching ---------- */
export function useFetch<T = any>(path: string | null, params?: Record<string, any>) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(!!path)
  const key = path ? path + JSON.stringify(params ?? {}) : ''
  const [tick, setTick] = useState(0)
  const reload = useCallback(() => setTick((t) => t + 1), [])
  const seq = useRef(0)
  useEffect(() => {
    if (!path) return
    const my = ++seq.current
    setLoading(true)
    api<T>(path, { params })
      .then((d) => { if (my === seq.current) { setData(d); setError(null) } })
      .catch((e) => { if (my === seq.current) setError(e.message) })
      .finally(() => { if (my === seq.current) setLoading(false) })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick])
  return { data, error, loading, reload, setData }
}

/* ---------- toasts ---------- */
type Toast = { id: number; kind: 'ok' | 'err' | 'info'; msg: string }
const ToastCtx = createContext<(kind: Toast['kind'], msg: string) => void>(() => {})
export const useToast = () => useContext(ToastCtx)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const push = useCallback((kind: Toast['kind'], msg: string) => {
    const id = Date.now() + Math.random()
    setItems((x) => [...x, { id, kind, msg }])
    setTimeout(() => setItems((x) => x.filter((t) => t.id !== id)), kind === 'err' ? 8000 : 4000)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 w-80" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`panel px-3 py-2 text-sm shadow-lg border-l-4 ${t.kind === 'ok' ? 'border-l-emerald-500' : t.kind === 'err' ? 'border-l-red-500' : 'border-l-accent'}`}>
            {t.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

/** Run an async action with a busy flag (prevents duplicate submits) and toast feedback. */
export function useAction() {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const run = useCallback(async <T,>(fn: () => Promise<T>, okMsg?: string): Promise<T | undefined> => {
    if (busy) return
    setBusy(true)
    try {
      const r = await fn()
      if (okMsg) toast('ok', okMsg)
      return r
    } catch (e: any) {
      toast('err', e.message ?? 'Action failed')
    } finally {
      setBusy(false)
    }
  }, [busy, toast])
  return { busy, run }
}

/* ---------- severity ---------- */
export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'] as const
export const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#38bdf8', informational: '#94a3b8',
}
const SEV_CLASS: Record<string, string> = {
  critical: 'text-red-300 bg-red-950/60 border-red-800/70',
  high: 'text-orange-300 bg-orange-950/50 border-orange-800/60',
  medium: 'text-yellow-300 bg-yellow-950/40 border-yellow-800/50',
  low: 'text-sky-300 bg-sky-950/40 border-sky-800/50',
  informational: 'text-slate-300 bg-slate-800/50 border-slate-700',
}

export function SevBadge({ sev }: { sev?: string | null }) {
  if (!sev) return <span className="text-faint">—</span>
  return <span className={`inline-block px-1.5 py-px rounded border text-[11px] font-medium uppercase tracking-wide ${SEV_CLASS[sev] ?? SEV_CLASS.informational}`}>{sev}</span>
}

export function Pill({ children, tone = 'default' }: { children: ReactNode; tone?: 'default' | 'ok' | 'warn' | 'accent' }) {
  const t = { default: 'text-mute border-line', ok: 'text-emerald-300 border-emerald-800/60', warn: 'text-yellow-300 border-yellow-800/60', accent: 'text-accent border-accent/40' }[tone]
  return <span className={`inline-block px-1.5 py-px rounded border text-[11px] ${t}`}>{children}</span>
}

export function Confidence({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  const label = value >= 0.75 ? 'High' : value >= 0.5 ? 'Moderate' : 'Low'
  return (
    <span className="inline-flex items-center gap-1.5" title={`Confidence ${pct}%: likelihood this is malicious given the evidence (independent of severity)`}>
      <span className="w-12 h-1.5 bg-line rounded overflow-hidden"><span className="block h-full bg-accent" style={{ width: `${pct}%` }} /></span>
      <span className="text-xs text-mute">{label} {pct}%</span>
    </span>
  )
}

/* ---------- layout bits ---------- */
export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <div className="flex items-center gap-2 text-mute text-sm p-4" role="status"><span className="w-3.5 h-3.5 rounded-full border-2 border-line border-t-accent animate-spin" />{label}…</div>
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="panel border-red-900/60 p-4 text-sm" role="alert">
      <div className="text-red-300 font-medium mb-1">Something went wrong</div>
      <div className="text-mute mb-3">{message}</div>
      {onRetry && <button className="btn btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="p-8 text-center">
      <div className="text-ink font-medium mb-1">{title}</div>
      {children && <div className="text-mute text-sm max-w-md mx-auto mb-3">{children}</div>}
      {action}
    </div>
  )
}

export function PageHeader({ title, crumbs, actions, sub }: { title: string; crumbs?: ReactNode; actions?: ReactNode; sub?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
      <div>
        {crumbs && <div className="text-xs text-faint mb-0.5">{crumbs}</div>}
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {sub && <div className="text-sm text-mute mt-0.5">{sub}</div>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Pagination({ page, pages, total, onPage }: { page: number; pages: number; total: number; onPage: (p: number) => void }) {
  return (
    <div className="flex items-center justify-between px-3 py-2 text-xs text-mute border-t border-line-soft">
      <span>{total.toLocaleString()} result{total === 1 ? '' : 's'}</span>
      <div className="flex items-center gap-2">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span>Page {page} of {pages}</span>
        <button className="btn btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  )
}

export function Drawer({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={onClose}>
      <aside role="dialog" aria-label={title} onClick={(e) => e.stopPropagation()}
        className={`h-full bg-panel border-l border-line shadow-2xl flex flex-col w-full ${wide ? 'max-w-3xl' : 'max-w-xl'}`}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-line">
          <h2 className="font-semibold text-sm">{title}</h2>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
      </aside>
    </div>
  )
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  useEffect(() => {
    if (!open) return
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div role="dialog" aria-label={title} aria-modal onClick={(e) => e.stopPropagation()} className="panel w-full max-w-lg shadow-2xl">
        <div className="panel-h normal-case text-sm text-ink"><span>{title}</span><button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close">✕</button></div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const toast = useToast()
  return (
    <button className="btn btn-ghost btn-sm !h-5 !px-1 text-faint hover:text-ink" title={`${label}: ${value}`} aria-label={`${label} ${value}`}
      onClick={() => navigator.clipboard?.writeText(value).then(() => toast('info', 'Copied to clipboard'), () => toast('err', 'Copy failed'))}>⧉</button>
  )
}

export function fmtTs(ts?: string | null) {
  return ts ? ts.replace('T', ' ').replace('Z', '') : '—'
}

export function download(url: string) {
  const a = document.createElement('a')
  a.href = url
  a.rel = 'noopener'
  a.click()
}
