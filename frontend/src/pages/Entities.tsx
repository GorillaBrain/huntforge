import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { EventDrawer, EventTable, NoData } from '../components'
import { ErrorBox, fmtTs, PageHeader, Pill, SevBadge, Spinner, useFetch } from '../ui'

const TYPES = [['ip', 'IP address'], ['user', 'User'], ['host', 'Host'], ['domain', 'Domain'], ['process', 'Process']]
const ENT = { ip: 'ip', user: 'user', host: 'host', domain: 'domain', process: 'process' } as const

function EntityDetail({ type, value }: { type: string; value: string }) {
  const nav = useNavigate()
  const { data, error, loading, reload } = useFetch<any>(`/api/entities/${type}/${encodeURIComponent(value)}`)
  const [open, setOpen] = useState<number | null>(null)
  if (loading && !data) return <Spinner />
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (!data) return null
  const o = data.observed
  const pivot = type === 'ip' ? `src_ip = "${value}" OR dst_ip = "${value}"` : `${({ user: 'username', host: 'hostname', domain: 'domain', process: 'process_name' } as any)[type]} = "${value}"`
  return (
    <div className="space-y-3">
      <div className="panel p-3 flex flex-wrap items-center gap-x-6 gap-y-1">
        <div><div className="text-xs text-mute">{TYPES.find((t) => t[0] === type)?.[1]}</div><div className="mono text-base">{value}</div></div>
        <div><div className="text-xs text-mute">Events</div><div className="tabular-nums">{o.event_count.toLocaleString()}</div></div>
        <div><div className="text-xs text-mute">First seen</div><div className="mono">{fmtTs(o.first_seen)}</div></div>
        <div><div className="text-xs text-mute">Last seen</div><div className="mono">{fmtTs(o.last_seen)}</div></div>
        <div className="ml-auto flex gap-2"><Link className="btn" to={`/explorer?q=${encodeURIComponent(pivot)}`}>Search events</Link><button className="btn btn-primary" onClick={() => api('/api/hunts', { method: 'POST', body: { title: `Hunt: ${value}`, query: pivot, hypothesis: `What else is ${value} involved in, and is the activity malicious?` } }).then((h) => nav(`/hunts/${h.id}`))}>Start hunt</button></div>
      </div>
      <div className="grid lg:grid-cols-2 gap-3">
        <div className="panel"><div className="panel-h">Observed activity</div><table className="w-full"><tbody>{o.activity.map((a: any, i: number) => <tr key={i}><td className="td">{a.event_type ?? 'unknown'}{a.outcome ? ` · ${a.outcome}` : ''}</td><td className="td text-right tabular-nums">{a.n}</td></tr>)}</tbody></table></div>
        <div className="panel"><div className="panel-h">Related detections ({data.detections.length})</div>
          {data.detections.length === 0 ? <p className="p-3 text-sm text-faint">No detections reference this entity.</p> : <ul>{data.detections.map((d: any) => <li key={d.id} className="px-3 py-1.5 border-b border-line-soft last:border-0 text-sm flex gap-2 items-center"><SevBadge sev={d.severity} /><Link className="link" to={`/detections/${d.id}`}>{d.id}</Link><span className="truncate">{d.title}</span></li>)}</ul>}</div>
        <div className="panel"><div className="panel-h">Linked cases ({data.cases.length})</div>
          {data.cases.length === 0 ? <p className="p-3 text-sm text-faint">Not linked to any case.</p> : <ul className="p-3 text-sm space-y-1">{data.cases.map((c: any) => <li key={c.id}><Link className="link" to={`/cases/${c.id}`}>{c.id}</Link> {c.title} <Pill>{c.status}</Pill></li>)}</ul>}</div>
        <div className="panel"><div className="panel-h">Related entities (observed co-occurrence)</div>
          <div className="p-3 space-y-2 text-sm">{Object.entries<any[]>(o.related).filter(([, v]) => v.length).map(([t, v]) => (
            <div key={t}><span className="text-xs uppercase text-mute mr-2">{t}</span>{v.slice(0, 6).map((x) => <Link key={x.value} className="link mono mr-3" to={`/entities?type=${(ENT as any)[t]}&value=${encodeURIComponent(x.value)}`}>{x.value} <span className="text-faint">({x.events})</span></Link>)}</div>))}</div></div>
      </div>
      <div className="panel"><div className="panel-h">External intelligence</div>
        <p className="p-3 text-sm text-mute">{data.external_intelligence.note}</p></div>
      <div className="panel"><div className="panel-h">Recent observed events</div><EventTable items={o.recent_events} onOpen={setOpen} compact selected={open} /></div>
      <EventDrawer eventId={open} onClose={() => setOpen(null)} />
    </div>
  )
}

export default function Entities() {
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const type = sp.get('type') ?? 'ip'
  const value = sp.get('value')
  const [q, setQ] = useState('')
  useEffect(() => setQ(''), [type])
  const ov = useFetch<any>('/api/overview')
  const list = useFetch<any>('/api/entities', { type, q })
  const setType = (t: string) => setSp({ type: t })
  if (ov.data && !ov.data.has_data) return <><PageHeader title="Entities" /><NoData onLoaded={() => { ov.reload(); list.reload() }} /></>
  return (
    <div>
      <PageHeader title="Entity Intelligence" sub="Observed facts about IPs, users, hosts, domains and processes. Observed data is kept separate from external intelligence." />
      <div className="grid lg:grid-cols-[18rem_1fr] gap-3">
        <div className="panel self-start">
          <div className="p-2 flex gap-1 flex-wrap">{TYPES.map(([t, l]) => <button key={t} className={`btn btn-sm ${type === t ? 'btn-primary' : ''}`} onClick={() => setType(t)}>{l}</button>)}</div>
          <div className="px-2 pb-2"><input className="input" aria-label="Filter entities" placeholder={`Filter ${type}s…`} value={q} onChange={(e) => setQ(e.target.value)} /></div>
          {list.error ? <div className="p-2"><ErrorBox message={list.error} onRetry={list.reload} /></div> : (
            <ul className="max-h-[60vh] overflow-y-auto border-t border-line-soft">{(list.data?.items ?? []).map((i: any) => (
              <li key={i.value}><button className={`w-full flex justify-between px-3 py-1.5 text-sm hover:bg-raised ${value === i.value ? 'bg-accent-soft' : ''}`} onClick={() => nav(`/entities?type=${type}&value=${encodeURIComponent(i.value)}`)}><span className="mono truncate">{i.value}</span><span className="text-mute tabular-nums">{i.events}</span></button></li>))}
              {list.data?.items.length === 0 && <li className="p-3 text-sm text-faint">No matching {type} entities.</li>}</ul>)}
        </div>
        <div>{value ? <EntityDetail key={type + value} type={type} value={value} /> : <div className="panel p-8 text-center text-mute text-sm">Select an entity, or use the global search, to see its observed activity.</div>}</div>
      </div>
    </div>
  )
}


