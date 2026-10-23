import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { AddToDialog, EntityLink, EventDrawer, EventTable, NoData } from '../components'
import { Confidence, Drawer, Empty, ErrorBox, fmtTs, PageHeader, Pagination, Pill, SEV_ORDER, SevBadge, Spinner, useAction, useFetch } from '../ui'

const STATUSES = ['open', 'investigating', 'false_positive', 'benign', 'resolved']

function Detail({ id, onChanged }: { id: string; onChanged: () => void }) {
  const nav = useNavigate()
  const { data: d, error, loading, reload } = useFetch<any>(`/api/detections/${id}`)
  const [ev, setEv] = useState<number | null>(null)
  const [adding, setAdding] = useState(false)
  const { busy, run } = useAction()
  if (loading && !d) return <Spinner />
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (!d) return null
  const setStatus = (status: string) => run(async () => { await api(`/api/detections/${id}`, { method: 'PATCH', body: { status } }); reload(); onChanged() }, `Marked ${status.replace('_', ' ')}`)
  const hunt = () => run(async () => { const h = await api('/api/hunts', { method: 'POST', body: { title: `Hunt: ${d.title}`, detection_id: id } }); nav(`/hunts/${h.id}`) }, 'Hunt started')
  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center gap-2 mb-1"><span className="mono text-mute">{d.id}</span><SevBadge sev={d.severity} /><Confidence value={d.confidence} /></div>
        <h3 className="text-base font-semibold">{d.title}</h3>
        <div className="text-xs text-mute mt-1">{d.rule_id} · {d.rule_name} · {d.technique} · detected {fmtTs(d.ts)}</div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-mute" htmlFor="st">Status</label>
        <select id="st" className="input !w-auto" disabled={busy} value={d.status} onChange={(e) => setStatus(e.target.value)}>{STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}</select>
        <button className="btn btn-primary" disabled={busy} onClick={hunt}>Start hunt</button>
        {d.case_id ? <Link className="btn" to={`/cases/${d.case_id}`}>Open {d.case_id}</Link> : <button className="btn" onClick={() => setAdding(true)}>Create / add to case…</button>}
      </div>
      <div className="panel p-3 text-sm"><div className="text-xs uppercase tracking-wide text-mute mb-1">Why it triggered</div>{d.explanation}
        <p className="text-xs text-faint mt-2">{d.note}</p></div>
      <section><h4 className="text-xs uppercase tracking-wide text-mute mb-1">Evidence fields</h4>
        <table className="w-full text-sm"><tbody>{Object.entries(d.evidence).map(([k, v]) => (
          <tr key={k} className="border-b border-line-soft"><th className="text-left font-normal text-mute py-1 pr-3 w-48 align-top">{k.replace(/_/g, ' ')}</th><td className="py-1 mono break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</td></tr>))}
        </tbody></table></section>
      <section><h4 className="text-xs uppercase tracking-wide text-mute mb-1">Entity</h4>
        {d.entity_type && <EntityLink type={d.entity_type} value={d.entity_value} />}</section>
      <section><h4 className="text-xs uppercase tracking-wide text-mute mb-1">Supporting events ({d.events.length})</h4>
        <div className="panel"><EventTable items={d.events} onOpen={setEv} compact selected={ev} /></div></section>
      <section><h4 className="text-xs uppercase tracking-wide text-mute mb-1">Recommended investigation steps</h4>
        <ol className="list-decimal list-inside text-sm space-y-1">{d.recommended_steps.map((s: string) => <li key={s}>{s}</li>)}</ol></section>
      <section className="text-sm"><h4 className="text-xs uppercase tracking-wide text-mute mb-1">Known false-positive risks and limitations</h4>
        <p className="text-mute">{d.false_positive_risks}</p><p className="text-mute mt-1">{d.limitations}</p></section>
      <EventDrawer eventId={ev} onClose={() => setEv(null)} />
      {adding && <AddToDialog open onClose={() => { setAdding(false); reload(); onChanged() }} detectionId={id} />}
    </div>
  )
}

export default function Detections() {
  const { id } = useParams()
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const page = Number(get('page') || 1)
  const sort = get('sort') || 'ts'
  const order = get('order') || 'desc'
  const params = { status: get('status'), severity: get('severity'), rule_id: get('rule_id'), q: get('q'), entity: get('entity'), sort, order, page }
  const { data, error, loading, reload } = useFetch<any>('/api/detections', params)
  const ov = useFetch<any>('/api/overview')
  const { busy, run } = useAction()
  const set = (patch: Record<string, string>) => { const n = new URLSearchParams(sp); for (const [k, v] of Object.entries(patch)) { if (v) n.set(k, v); else n.delete(k) }; if (!('page' in patch)) n.delete('page'); setSp(n) }
  const close = () => nav(`/detections${sp.toString() ? '?' + sp.toString() : ''}`)
  const th = (k: string, l: string) => <th className="th"><button className="hover:text-ink" onClick={() => set({ sort: k, order: sort === k && order === 'desc' ? 'asc' : 'desc' })}>{l}{sort === k ? (order === 'asc' ? ' ▲' : ' ▼') : ''}</button></th>

  if (ov.data && !ov.data.has_data) return <><PageHeader title="Detection Center" /><NoData onLoaded={() => { ov.reload(); reload() }} /></>
  return (
    <div>
      <PageHeader title="Detection Center" sub="Suspicious patterns found by deterministic rules. A detection is not a confirmed attack." actions={
        <button className="btn" disabled={busy} onClick={() => run(async () => { const r = await api('/api/detections/run', { method: 'POST' }); reload(); return r }, 'Rules re-run; existing statuses preserved')}>{busy ? 'Running…' : 'Re-run enabled rules'}</button>} />
      <div className="flex flex-wrap gap-2 mb-3">
        <input className="input !w-64" aria-label="Search detections" placeholder="Search title, entity or ID" defaultValue={get('q')} key={get('q')} onKeyDown={(e) => e.key === 'Enter' && set({ q: (e.target as HTMLInputElement).value })} />
        <select className="input !w-auto" aria-label="Severity" value={get('severity')} onChange={(e) => set({ severity: e.target.value })}><option value="">Severity: any</option>{SEV_ORDER.map((s) => <option key={s}>{s}</option>)}</select>
        <select className="input !w-auto" aria-label="Status" value={get('status')} onChange={(e) => set({ status: e.target.value })}><option value="">Status: any</option>{STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}</select>
        <select className="input !w-auto" aria-label="Rule" value={get('rule_id')} onChange={(e) => set({ rule_id: e.target.value })}><option value="">Rule: any</option>{Array.from({ length: 8 }, (_, i) => `HF-00${i + 1}`).map((s) => <option key={s}>{s}</option>)}</select>
        {get('entity') && <button className="btn" onClick={() => set({ entity: '' })}>Entity: {get('entity')} ✕</button>}
        <button className="btn btn-ghost" onClick={() => setSp({})}>Clear</button>
      </div>
      <div className={`panel ${loading && data ? 'opacity-70' : ''}`}>
        {error ? <div className="p-3"><ErrorBox message={error} onRetry={reload} /></div> : !data ? <Spinner /> : data.items.length === 0 ? (
          <Empty title="No detections match">Adjust filters, or re-run the rules if you have just ingested data.</Empty>
        ) : (
          <>
            <div className="overflow-auto"><table className="w-full min-w-[900px]"><thead><tr>
              <th className="th">ID</th>{th('severity', 'Severity')}{th('confidence', 'Confidence')}<th className="th">Detection</th>{th('rule', 'Rule')}{th('ts', 'Detected (UTC)')}<th className="th">Events</th>{th('status', 'Status')}<th className="th">Case</th></tr></thead>
              <tbody>{data.items.map((d: any) => (
                <tr key={d.id} tabIndex={0} className={`cursor-pointer hover:bg-raised ${id === d.id ? 'bg-accent-soft' : ''}`} onClick={() => nav(`/detections/${d.id}${sp.toString() ? '?' + sp : ''}`)} onKeyDown={(e) => e.key === 'Enter' && nav(`/detections/${d.id}`)}>
                  <td className="td mono text-mute">{d.id}</td><td className="td"><SevBadge sev={d.severity} /></td><td className="td"><Confidence value={d.confidence} /></td>
                  <td className="td">{d.title}{d.group_size > 1 && <span className="ml-2"><Pill tone="accent">{d.group_size} similar</Pill></span>}</td>
                  <td className="td mono text-mute">{d.rule_id}</td><td className="td mono whitespace-nowrap">{fmtTs(d.ts)}</td><td className="td tabular-nums">{d.event_count}</td>
                  <td className="td"><Pill tone={d.status === 'open' ? 'warn' : d.status === 'resolved' || d.status === 'benign' || d.status === 'false_positive' ? 'ok' : 'accent'}>{d.status.replace('_', ' ')}</Pill></td>
                  <td className="td mono">{d.case_id ?? '—'}</td></tr>))}</tbody></table></div>
            <Pagination page={data.page} pages={data.pages} total={data.total} onPage={(p) => set({ page: String(p) })} />
          </>)}
      </div>
      <Drawer open={!!id} onClose={close} title={id ?? ''} wide>{id && <Detail id={id} onChanged={reload} />}</Drawer>
    </div>
  )
}

