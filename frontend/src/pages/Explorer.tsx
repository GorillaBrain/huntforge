import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { apiUrl } from '../api'
import { api } from '../api'
import { EventDrawer, EventTable, NoData } from '../components'
import { Empty, ErrorBox, PageHeader, Pagination, Spinner, download, useAction, useFetch } from '../ui'

const FIELDS = ['username', 'hostname', 'src_ip', 'dst_ip', 'dst_port', 'event_type', 'outcome', 'source', 'severity', 'process_name', 'parent_process', 'command_line', 'domain', 'country', 'bytes_out', 'message']
const OPS = [['=', 'equals'], ['!=', 'not equals'], ['~', 'contains'], ['>', '>'], ['<', '<'], ['>=', '≥'], ['<=', '≤']]

type Row = { field: string; op: string; value: string }

function QueryBuilder({ onApply }: { onApply: (q: string) => void }) {
  const [rows, setRows] = useState<Row[]>([{ field: 'username', op: '=', value: '' }])
  const [join, setJoin] = useState<'AND' | 'OR'>('AND')
  const upd = (i: number, p: Partial<Row>) => setRows((r) => r.map((x, j) => (j === i ? { ...x, ...p } : x)))
  const build = () => rows.filter((r) => r.value.trim()).map((r) => `${r.field} ${r.op} "${r.value.replace(/"/g, '\\"')}"`).join(` ${join} `)
  return (
    <div className="panel p-3 mb-3">
      <div className="text-xs text-mute mb-2">Build a query (combined with <select className="bg-bg border border-line rounded text-xs" aria-label="Join" value={join} onChange={(e) => setJoin(e.target.value as any)}><option>AND</option><option>OR</option></select>)</div>
      <div className="space-y-2">
        {rows.map((r, i) => (
          <div key={i} className="flex gap-2">
            <select className="input !w-40" aria-label="Field" value={r.field} onChange={(e) => upd(i, { field: e.target.value })}>{FIELDS.map((f) => <option key={f}>{f}</option>)}</select>
            <select className="input !w-28" aria-label="Operator" value={r.op} onChange={(e) => upd(i, { op: e.target.value })}>{OPS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
            <input className="input" aria-label="Value" value={r.value} placeholder="value (use * as wildcard with equals)" onChange={(e) => upd(i, { value: e.target.value })} onKeyDown={(e) => e.key === 'Enter' && onApply(build())} />
            <button className="btn" aria-label="Remove condition" disabled={rows.length === 1} onClick={() => setRows((x) => x.filter((_, j) => j !== i))}>−</button>
          </div>
        ))}
      </div>
      <div className="flex gap-2 mt-2">
        <button className="btn btn-sm" onClick={() => setRows((r) => [...r, { field: 'hostname', op: '=', value: '' }])}>+ Add condition</button>
        <button className="btn btn-sm btn-primary" onClick={() => onApply(build())}>Run query</button>
      </div>
    </div>
  )
}

const HELP = `Fields: username, hostname, src_ip, dst_ip, dst_port, event_type, outcome, source, severity, process_name, command_line, domain, country, bytes_out, message
Operators: =  !=  ~ (contains)  >  <  >=  <=   ·  value* wildcard with =
Boolean: AND, OR, NOT, parentheses. Adjacent terms are ANDed.
A bare word or "quoted phrase" searches users, hosts, IPs, domains, processes, commands and the raw event.
Examples:
  outcome = failure AND src_ip = "203.0.113.45"
  (event_type = process_create) AND command_line ~ "-enc"
  dst_port > 1024 AND NOT dst_ip = "10.*"`

export default function Explorer() {
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const q = get('q')
  const [draft, setDraft] = useState(q)
  useEffect(() => setDraft(q), [q])
  const [open, setOpen] = useState<number | null>(null)
  const [builder, setBuilder] = useState(false)
  const [help, setHelp] = useState(false)
  const page = Number(get('page') || 1)
  const sort = get('sort') || 'ts'
  const order = get('order') || 'desc'
  const params = { q, event_type: get('event_type'), outcome: get('outcome'), severity: get('severity'), hostname: get('hostname'), username: get('username'), src_ip: get('src_ip'), dst_ip: get('dst_ip'), source: get('source'), since: get('since'), until: get('until'), ingestion_id: get('ingestion_id'), sort, order, page, page_size: 50 }
  const { data, error, loading, reload } = useFetch<any>('/api/events', params)
  const facets = useFetch<any>('/api/events/facets')
  const saved = useFetch<any[]>('/api/events/saved/searches')
  const { run } = useAction()

  const set = (patch: Record<string, string>) => {
    const n = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(patch)) { if (v) n.set(k, v); else n.delete(k) }
    if (!('page' in patch)) n.delete('page')
    setSp(n, { replace: false })
  }
  const exportUrl = apiUrl('/api/events/export', { ...params, page: undefined, page_size: undefined })

  if (facets.data && Object.values<any>(facets.data).every((v) => v.length === 0)) return <><PageHeader title="Log Explorer" /><NoData onLoaded={() => { facets.reload(); reload() }} /></>

  return (
    <div>
      <PageHeader title="Log Explorer" sub="Server-side search over normalized events. Click a row for the original event." actions={<>
        <button className="btn" onClick={() => setBuilder((b) => !b)}>{builder ? 'Hide' : 'Query builder'}</button>
        <button className="btn" onClick={() => download(exportUrl)}>Export CSV</button>
      </>} />
      <form className="flex gap-2 mb-2" onSubmit={(e) => { e.preventDefault(); set({ q: draft }) }}>
        <input className="input mono !h-9" aria-label="Search query" value={draft} onChange={(e) => setDraft(e.target.value)} placeholder='e.g. outcome = failure AND src_ip = "203.0.113.45"   or   powershell' />
        <button className="btn btn-primary !h-9" type="submit">Search</button>
        <button className="btn !h-9" type="button" onClick={() => { setDraft(''); setSp({}) }}>Reset</button>
      </form>
      <div className="flex flex-wrap items-center gap-2 mb-3 text-xs">
        <button className="link" onClick={() => setHelp((h) => !h)}>{help ? 'Hide' : 'Show'} query syntax</button>
        {q && <button className="link" onClick={() => run(async () => { const name = prompt('Name this search'); if (name) { await api('/api/events/saved/searches', { method: 'POST', body: { name, query: q } }); saved.reload() } })}>Save this search</button>}
        {(saved.data ?? []).length > 0 && (
          <select className="input !w-auto !h-7 text-xs" aria-label="Saved searches" value="" onChange={(e) => { const s = saved.data!.find((x) => String(x.id) === e.target.value); if (s) set({ q: s.query }) }}>
            <option value="">Saved searches…</option>{saved.data!.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>)}
        {(saved.data ?? []).length > 0 && <button className="link" onClick={() => run(async () => { const id = prompt('Delete which saved search? Enter its name') ; const s = saved.data!.find((x) => x.name === id); if (s) { await api(`/api/events/saved/searches/${s.id}`, { method: 'DELETE' }); saved.reload() } })}>Delete saved…</button>}
      </div>
      {help && <pre className="mono panel p-3 mb-3 whitespace-pre-wrap text-mute">{HELP}</pre>}
      {builder && <QueryBuilder onApply={(b) => { setDraft(b); set({ q: b }) }} />}
      <div className="flex flex-wrap gap-2 mb-3">
        {([['event_type', 'Event type'], ['outcome', 'Outcome'], ['severity', 'Severity'], ['source', 'Source'], ['hostname', 'Host'], ['username', 'User']] as const).map(([k, l]) => (
          <select key={k} className="input !w-auto" aria-label={l} value={get(k)} onChange={(e) => set({ [k]: e.target.value })}>
            <option value="">{l}: any</option>{(facets.data?.[k] ?? []).map((v: string) => <option key={v}>{v}</option>)}
          </select>))}
        <input className="input !w-36" aria-label="Source IP" placeholder="Source IP" value={get('src_ip')} onChange={(e) => set({ src_ip: e.target.value })} />
        <input className="input !w-36" aria-label="Destination IP" placeholder="Destination IP" value={get('dst_ip')} onChange={(e) => set({ dst_ip: e.target.value })} />
        <input className="input !w-48" aria-label="From" type="datetime-local" value={get('since').replace('Z', '').slice(0, 16)} onChange={(e) => set({ since: e.target.value ? e.target.value + ':00Z' : '' })} />
        <input className="input !w-48" aria-label="To" type="datetime-local" value={get('until').replace('Z', '').slice(0, 16)} onChange={(e) => set({ until: e.target.value ? e.target.value + ':59Z' : '' })} />
      </div>
      <div className={`panel ${loading && data ? 'opacity-70' : ''}`}>
        {error ? <div className="p-3"><ErrorBox message={error} onRetry={reload} /></div> : !data ? <Spinner /> : data.items.length === 0 ? (
          <Empty title="No events match" action={<button className="btn" onClick={() => { setDraft(''); setSp({}) }}>Clear all filters</button>}>Loosen the query or filters, or check the time range.</Empty>
        ) : (
          <>
            <EventTable items={data.items} onOpen={setOpen} selected={open} sort={sort} order={order} onSort={(c) => set({ sort: c, order: sort === c && order === 'desc' ? 'asc' : 'desc' })} />
            <Pagination page={data.page} pages={data.pages} total={data.total} onPage={(p) => set({ page: String(p) })} />
          </>)}
      </div>
      <EventDrawer eventId={open} onClose={() => setOpen(null)} onPivot={(p) => { set({ q: p }); setOpen(null) }} />
    </div>
  )
}

