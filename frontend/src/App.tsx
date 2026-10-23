import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { apiBase } from './api'
import { Spinner, useFetch } from './ui'

const Overview = lazy(() => import('./pages/Overview'))
const Explorer = lazy(() => import('./pages/Explorer'))
const Detections = lazy(() => import('./pages/Detections'))
const Hunts = lazy(() => import('./pages/Hunts'))
const Cases = lazy(() => import('./pages/Cases'))
const Rules = lazy(() => import('./pages/Rules'))
const Entities = lazy(() => import('./pages/Entities'))
const Reports = lazy(() => import('./pages/Reports'))
const DataSources = lazy(() => import('./pages/DataSources'))

const NAV = [
  { to: '/', label: 'Overview', icon: '▦', end: true },
  { to: '/explorer', label: 'Log Explorer', icon: '≡' },
  { to: '/detections', label: 'Detections', icon: '⚑' },
  { to: '/hunts', label: 'Threat Hunting', icon: '◎' },
  { to: '/cases', label: 'Cases', icon: '▤' },
  { to: '/rules', label: 'Detection Rules', icon: '⚙' },
  { to: '/entities', label: 'Entities', icon: '◇' },
  { to: '/reports', label: 'Reports', icon: '▧' },
  { to: '/data', label: 'Data Sources', icon: '⇪' },
]

const TITLES: Record<string, string> = Object.fromEntries(NAV.map((n) => [n.to, n.label]))

function GlobalSearch() {
  const [v, setV] = useState('')
  const [open, setOpen] = useState(false)
  const nav = useNavigate()
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName)) { e.preventDefault(); ref.current?.focus() }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])
  const term = v.trim()
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(term)
  const go = (to: string) => { setOpen(false); setV(''); ref.current?.blur(); nav(to) }
  const options = term ? [
    { label: `Search logs for “${term}”`, to: `/explorer?q=${encodeURIComponent(/[=:~()<>]/.test(term) ? term : `"${term}"`)}` },
    ...(isIp ? [{ label: `Open IP entity ${term}`, to: `/entities?type=ip&value=${encodeURIComponent(term)}` }] : [
      { label: `Open user entity “${term}”`, to: `/entities?type=user&value=${encodeURIComponent(term)}` },
      { label: `Open host entity “${term}”`, to: `/entities?type=host&value=${encodeURIComponent(term)}` }]),
    { label: `Find detections matching “${term}”`, to: `/detections?q=${encodeURIComponent(term)}` },
  ] : []
  return (
    <div className="relative w-full max-w-md">
      <input ref={ref} className="input pr-8" value={v} placeholder="Search logs, IPs, users, hosts…   ( / )" aria-label="Global search"
        onChange={(e) => { setV(e.target.value); setOpen(true) }} onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => { if (e.key === 'Enter' && options[0]) go(options[0].to); if (e.key === 'Escape') ref.current?.blur() }} />
      {open && options.length > 0 && (
        <ul className="absolute z-40 mt-1 w-full panel shadow-xl py-1" role="listbox">
          {options.map((o) => (
            <li key={o.to}><button className="w-full text-left px-3 py-1.5 text-sm hover:bg-raised" onMouseDown={() => go(o.to)}>{o.label}</button></li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Status() {
  const { data, error } = useFetch<any>('/api/health')
  const ov = useFetch<any>('/api/overview')
  const ok = !!data && !error
  return (
    <div className="hidden md:flex items-center gap-3 text-xs text-mute">
      <span className="flex items-center gap-1.5" title={error ?? `API: ${apiBase}`}>
        <span className={`w-2 h-2 rounded-full ${ok ? 'bg-emerald-500' : error ? 'bg-red-500' : 'bg-slate-500'}`} />
        {ok ? 'API connected' : error ? 'API unreachable' : 'Connecting'}
      </span>
      {ov.data && <span>{ov.data.totals.events_ingested.toLocaleString()} events</span>}
    </div>
  )
}

export default function App() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('hf.nav') === '1')
  const [mobile, setMobile] = useState(false)
  const loc = useLocation()
  useEffect(() => { localStorage.setItem('hf.nav', collapsed ? '1' : '0') }, [collapsed])
  useEffect(() => setMobile(false), [loc.pathname])
  const base = '/' + loc.pathname.split('/')[1]
  const title = TITLES[base] ?? 'HuntForge'
  const sub = loc.pathname.split('/').slice(2).join(' / ')

  return (
    <div className="h-full flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-accent focus:text-black focus:px-3 focus:py-1">Skip to content</a>
      <nav aria-label="Primary" className={`${mobile ? 'fixed inset-y-0 left-0 z-40 shadow-2xl' : 'hidden'} md:flex flex-col shrink-0 bg-panel border-r border-line ${collapsed ? 'md:w-14' : 'md:w-56'} w-56 transition-[width]`}>
        <Link to="/" className="flex items-center gap-2.5 px-3 h-12 border-b border-line">
          <span className="w-7 h-7 rounded bg-accent-soft border border-accent/40 grid place-items-center text-accent font-bold text-sm shrink-0">H</span>
          {!collapsed && <span className="font-semibold tracking-tight">HuntForge</span>}
        </Link>
        <ul className="flex-1 py-2 px-2 space-y-0.5 overflow-y-auto">
          {NAV.map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} end={n.end} title={n.label}
                className={({ isActive }) => `flex items-center gap-2.5 h-8 px-2 rounded text-sm ${isActive ? 'bg-accent-soft text-accent' : 'text-mute hover:bg-raised hover:text-ink'}`}>
                <span className="w-4 text-center shrink-0" aria-hidden>{n.icon}</span>
                {!collapsed && <span className="truncate">{n.label}</span>}
              </NavLink>
            </li>
          ))}
        </ul>
        <button className="hidden md:flex btn btn-ghost btn-sm m-2 justify-start" onClick={() => setCollapsed((c) => !c)} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
          {collapsed ? '»' : '« Collapse'}
        </button>
      </nav>
      {mobile && <div className="fixed inset-0 z-30 bg-black/50 md:hidden" onClick={() => setMobile(false)} />}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-12 shrink-0 border-b border-line bg-panel flex items-center gap-3 px-3">
          <button className="btn btn-ghost btn-sm md:hidden" aria-label="Open navigation" onClick={() => setMobile(true)}>☰</button>
          <div className="hidden lg:block text-sm text-mute shrink-0">
            <span className="text-faint">Workspace /</span> <span className="text-ink">Default</span>
            <span className="text-faint"> / </span>{title}{sub && <span className="text-faint"> / {sub}</span>}
          </div>
          <div className="flex-1 flex justify-center"><GlobalSearch /></div>
          <Status />
        </header>
        <main id="main" className="flex-1 overflow-y-auto p-4 md:p-5">
          <Suspense fallback={<Spinner />}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/explorer" element={<Explorer />} />
              <Route path="/detections" element={<Detections />} />
              <Route path="/detections/:id" element={<Detections />} />
              <Route path="/hunts" element={<Hunts />} />
              <Route path="/hunts/:id" element={<Hunts />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/cases/:id" element={<Cases />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/entities" element={<Entities />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/reports/:id" element={<Reports />} />
              <Route path="/data" element={<DataSources />} />
              <Route path="*" element={<div className="p-8 text-center text-mute">Page not found. <Link className="link" to="/">Go to overview</Link></div>} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </div>
  )
}
