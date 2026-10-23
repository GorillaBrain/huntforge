import { useMemo } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { EntityLink, NoData } from '../components'
import { ErrorBox, fmtTs, PageHeader, SEV_COLOR, SEV_ORDER, SevBadge, Spinner, useFetch } from '../ui'

const RANGES = [{ v: '', l: 'All data' }, { v: '6', l: 'Last 6 h of data' }, { v: '24', l: 'Last 24 h of data' }, { v: '168', l: 'Last 7 d of data' }]
const tip = { contentStyle: { background: '#12151b', border: '1px solid #262b36', fontSize: 12 }, cursor: { fill: '#ffffff08' } }

function Metric({ label, value, to, tone }: { label: string; value: number; to?: string; tone?: string }) {
  const body = (
    <div className="panel px-3 py-2.5 hover:border-accent/50 transition-colors h-full">
      <div className="text-xs text-mute">{label}</div>
      <div className={`text-2xl font-semibold tabular-nums mt-0.5 ${tone ?? ''}`}>{value.toLocaleString()}</div>
    </div>
  )
  return to ? <Link to={to}>{body}</Link> : body
}

function TopList({ title, items, render }: { title: string; items: { value: string; count: number }[]; render: (v: string) => JSX.Element }) {
  const max = Math.max(1, ...items.map((i) => i.count))
  return (
    <div className="panel">
      <div className="panel-h">{title}</div>
      <ul className="p-2 space-y-1">
        {items.length === 0 && <li className="text-sm text-faint px-1">No data</li>}
        {items.map((i) => (
          <li key={i.value} className="relative flex justify-between items-center text-sm px-1 py-0.5">
            <span className="absolute inset-y-0 left-0 bg-accent/10 rounded" style={{ width: `${(i.count / max) * 100}%` }} />
            <span className="relative truncate">{render(i.value)}</span><span className="relative tabular-nums text-mute ml-2">{i.count}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function Overview() {
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const range = sp.get('range') ?? ''
  const severity = sp.get('severity') ?? ''
  const source = sp.get('source') ?? ''
  const category = sp.get('category') ?? ''
  const base = useFetch<any>('/api/overview')
  const since = useMemo(() => {
    const max = base.data?.data_range?.max
    if (!range || !max) return undefined
    return new Date(new Date(max).getTime() - Number(range) * 3600_000).toISOString().replace(/\.\d+Z$/, 'Z')
  }, [range, base.data])
  const { data, error, loading, reload } = useFetch<any>('/api/overview', { since, severity, source, category })
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }) }

  const series = useMemo(() => {
    const m = new Map<string, any>()
    for (const r of data?.detections_over_time ?? []) { const o = m.get(r.bucket) ?? { bucket: r.bucket }; o[r.severity] = r.n; m.set(r.bucket, o) }
    return [...m.values()]
  }, [data])

  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (!data) return <Spinner />
  if (!data.has_data) return <><PageHeader title="Overview" /><NoData onLoaded={() => { base.reload(); reload() }} /></>
  const t = data.totals
  const rangeQ = since ? `&since=${encodeURIComponent(since)}` : ''
  const label = (b: string) => b.slice(5, 13).replace('T', ' ') + 'h'

  return (
    <div className={loading ? 'opacity-70 transition-opacity' : ''}>
      <PageHeader title="Overview" sub={`Data spans ${fmtTs(data.data_range.min)} → ${fmtTs(data.data_range.max)} (UTC). All figures are computed from stored events.`}
        actions={<>
          <select className="input !w-auto" aria-label="Time range" value={range} onChange={(e) => set('range', e.target.value)}>{RANGES.map((r) => <option key={r.v} value={r.v}>{r.l}</option>)}</select>
          <select className="input !w-auto" aria-label="Severity" value={severity} onChange={(e) => set('severity', e.target.value)}><option value="">All severities</option>{SEV_ORDER.map((s) => <option key={s}>{s}</option>)}</select>
          <select className="input !w-auto" aria-label="Event source" value={source} onChange={(e) => set('source', e.target.value)}><option value="">All sources</option>{data.sources.map((s: string) => <option key={s}>{s}</option>)}</select>
          <select className="input !w-auto" aria-label="Detection category" value={category} onChange={(e) => set('category', e.target.value)}><option value="">All detection types</option>{['HF-001', 'HF-002', 'HF-003', 'HF-004', 'HF-005', 'HF-006', 'HF-007', 'HF-008'].map((s) => <option key={s}>{s}</option>)}</select>
        </>} />
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3 mb-4">
        <Metric label="Events ingested (total)" value={t.events_ingested} to="/explorer" />
        <Metric label="Events in selected period" value={t.events_in_period} to={`/explorer?${rangeQ.slice(1)}${source ? `&source=${source}` : ''}`} />
        <Metric label="Active investigations" value={t.active_investigations} to="/cases" />
        <Metric label="Open detections" value={t.open_detections} to="/detections?status=open" />
        <Metric label="High / critical open" value={t.high_critical} to="/detections?severity=high" tone="text-orange-300" />
        <Metric label="Failed records (ingestion)" value={data.failed_records_total} to="/data" />
      </div>
      <div className="grid lg:grid-cols-3 gap-3 mb-3">
        <div className="panel lg:col-span-2">
          <div className="panel-h">Detections over time (by severity)</div>
          <div className="h-56 p-2">
            {series.length === 0 ? <div className="h-full grid place-items-center text-sm text-faint">No detections in this selection</div> : (
              <ResponsiveContainer><BarChart data={series}><CartesianGrid stroke="#1c2029" vertical={false} />
                <XAxis dataKey="bucket" tickFormatter={label} stroke="#667085" fontSize={11} /><YAxis allowDecimals={false} stroke="#667085" fontSize={11} width={28} />
                <Tooltip {...tip} labelFormatter={(b) => fmtTs(b as string)} />
                {[...SEV_ORDER].reverse().map((s) => <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLOR[s]} onClick={() => nav(`/detections?severity=${s}`)} cursor="pointer" />)}
              </BarChart></ResponsiveContainer>)}
          </div>
        </div>
        <div className="panel">
          <div className="panel-h">Detections by rule <span className="normal-case font-normal text-faint">click to filter</span></div>
          <ul className="p-2 space-y-1">
            {data.top_detection_types.length === 0 && <li className="text-sm text-faint px-1">No detections</li>}
            {data.top_detection_types.map((r: any) => (
              <li key={r.rule_id}><Link to={`/detections?rule_id=${r.rule_id}`} className="flex justify-between text-sm px-1 py-1 rounded hover:bg-raised"><span><span className="mono text-mute">{r.rule_id}</span> <RuleName id={r.rule_id} /></span><span className="tabular-nums">{r.n}</span></Link></li>
            ))}
          </ul>
        </div>
      </div>
      <div className="panel mb-3">
        <div className="panel-h">Event volume</div>
        <div className="h-36 p-2"><ResponsiveContainer><LineChart data={data.events_over_time}><CartesianGrid stroke="#1c2029" vertical={false} /><XAxis dataKey="bucket" tickFormatter={label} stroke="#667085" fontSize={11} /><YAxis stroke="#667085" fontSize={11} width={36} /><Tooltip {...tip} labelFormatter={(b) => fmtTs(b as string)} /><Line dataKey="n" name="events" stroke="#4f9cf9" dot={false} strokeWidth={1.5} /></LineChart></ResponsiveContainer></div>
      </div>
      <div className="grid md:grid-cols-3 gap-3 mb-3">
        <TopList title="Top source IPs" items={data.top_source_ips} render={(v) => <EntityLink type="ip" value={v} />} />
        <TopList title="Top users" items={data.top_users} render={(v) => <EntityLink type="user" value={v} />} />
        <TopList title="Top hosts" items={data.top_hosts} render={(v) => <EntityLink type="host" value={v} />} />
      </div>
      <div className="grid lg:grid-cols-3 gap-3">
        <div className="panel lg:col-span-2">
          <div className="panel-h">Recent events <Link className="link normal-case font-normal" to="/explorer">Open explorer</Link></div>
          <table className="w-full"><tbody>
            {data.recent_events.map((e: any) => (
              <tr key={e.id} className="hover:bg-raised cursor-pointer" onClick={() => nav(`/explorer?q=${encodeURIComponent(`src_ip = "${e.src_ip ?? ''}"`)}`)}>
                <td className="td mono whitespace-nowrap">{fmtTs(e.ts)}</td><td className="td">{e.event_type}</td><td className="td mono">{e.username ?? e.hostname ?? ''}</td><td className="td mono">{e.src_ip ?? ''}</td>
              </tr>))}
          </tbody></table>
        </div>
        <div className="space-y-3">
          <div className="panel">
            <div className="panel-h">Ingestion status</div>
            <ul className="p-2 space-y-1.5 text-sm">
              {data.ingestions.map((i: any) => <li key={i.id} className="flex justify-between gap-2"><span className="truncate" title={i.filename}>{i.filename}</span><span className="text-mute shrink-0">{i.stored_records.toLocaleString()} ok{i.failed_records ? ` · ${i.failed_records} failed` : ''}</span></li>)}
            </ul>
          </div>
          <div className="panel">
            <div className="panel-h">Recent investigation activity</div>
            <ul className="p-2 space-y-1.5 text-sm max-h-60 overflow-y-auto">
              {data.recent_activity.length === 0 && <li className="text-faint">No activity yet</li>}
              {data.recent_activity.map((a: any) => <li key={a.id} className="flex gap-2"><span className="mono text-faint shrink-0">{a.ts.slice(11, 16)}</span><span className="truncate" title={a.detail ?? ''}>{a.action.replace(/_/g, ' ')}{a.target_id ? ` · ${a.target_id}` : ''}</span></li>)}
            </ul>
          </div>
        </div>
      </div>
      <p className="text-xs text-faint mt-4">Severity filter applies to detections. <SevBadge sev="informational" /> metrics reflect open or investigating findings only.</p>
    </div>
  )
}

function RuleName({ id }: { id: string }) {
  const { data } = useFetch<any[]>('/api/rules')
  return <span>{data?.find((r) => r.id === id)?.name ?? ''}</span>
}

