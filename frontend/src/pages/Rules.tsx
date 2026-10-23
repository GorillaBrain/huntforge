import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { NoData } from '../components'
import { ErrorBox, fmtTs, PageHeader, Pill, SevBadge, Spinner, useAction, useFetch, Confidence } from '../ui'

function RuleDetail({ r, onChanged, hasData }: { r: any; onChanged: () => void; hasData: boolean }) {
  const { busy, run } = useAction()
  const [params, setParams] = useState(JSON.stringify(r.params, null, 2))
  const [result, setResult] = useState<any>(null)
  const [test, setTest] = useState<any>(null)
  const ings = useFetch<any>('/api/ingestion')
  const [ing, setIng] = useState('')
  const save = () => run(async () => {
    let p: any
    try { p = JSON.parse(params) } catch { throw new Error('Parameters must be valid JSON') }
    await api(`/api/rules/${r.id}`, { method: 'PATCH', body: { params: p } }); onChanged()
  }, 'Parameters saved')
  return (
    <div className="p-4 space-y-4 border-t border-line-soft bg-bg/40">
      <div className="grid lg:grid-cols-2 gap-4 text-sm">
        <div className="space-y-3">
          <div><div className="text-xs uppercase tracking-wide text-mute mb-1">What it detects</div>{r.description}<div className="text-mute mt-1">ATT&amp;CK: {r.technique}</div></div>
          <div><div className="text-xs uppercase tracking-wide text-mute mb-1">Logic</div><p className="text-mute">{r.logic}</p></div>
          <div><div className="text-xs uppercase tracking-wide text-mute mb-1">Required data sources</div><ul className="list-disc list-inside text-mute">{r.data_sources.map((d: string) => <li key={d}>{d}</li>)}</ul></div>
        </div>
        <div className="space-y-3">
          <div><div className="text-xs uppercase tracking-wide text-mute mb-1">False-positive risks</div><p className="text-mute">{r.false_positives}</p></div>
          <div><div className="text-xs uppercase tracking-wide text-mute mb-1">Limitations</div><p className="text-mute">{r.limitations}</p></div>
          <div><div className="text-xs uppercase tracking-wide text-mute mb-1">Analyst follow-up</div><ol className="list-decimal list-inside text-mute">{r.recommended_steps.map((d: string) => <li key={d}>{d}</li>)}</ol></div>
        </div>
      </div>
      {Object.keys(r.default_params).length > 0 && (
        <div><label className="label" htmlFor={`p-${r.id}`}>Parameters (JSON). Defaults: <span className="mono">{JSON.stringify(r.default_params)}</span></label>
          <textarea id={`p-${r.id}`} className="input mono" rows={Math.min(8, params.split('\n').length)} value={params} onChange={(e) => setParams(e.target.value)} />
          <div className="mt-2 flex gap-2"><button className="btn btn-sm btn-primary" disabled={busy} onClick={save}>Save parameters</button><button className="btn btn-sm" onClick={() => setParams(JSON.stringify(r.default_params, null, 2))}>Reset to defaults</button></div></div>)}
      <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-line-soft">
        <select className="input !w-auto" aria-label="Dataset" value={ing} onChange={(e) => setIng(e.target.value)}><option value="">All datasets</option>{(ings.data?.items ?? []).map((i: any) => <option key={i.id} value={i.id}>#{i.id} {i.filename}</option>)}</select>
        <button className="btn btn-primary" disabled={busy || !hasData} onClick={() => run(async () => setResult(await api(`/api/rules/${r.id}/run`, { method: 'POST', params: { ingestion_id: ing } })))}>Run rule (dry run)</button>
        <button className="btn" disabled={busy || !hasData} onClick={() => run(async () => { setTest(await api(`/api/rules/${r.id}/test`)) })}>Run sample test</button>
      </div>
      {result && <div className="panel"><div className="panel-h">Dry-run result: {result.match_count} match(es) · nothing stored</div>
        {result.matches.length === 0 ? <p className="p-3 text-sm text-faint">No matches with the current parameters.</p> : <table className="w-full"><tbody>{result.matches.map((m: any) => (
          <tr key={m.id}><td className="td"><SevBadge sev={m.severity} /></td><td className="td"><Confidence value={m.confidence} /></td><td className="td">{m.title}<div className="text-xs text-faint mono">{m.event_ids.length} events · {fmtTs(m.ts)}</div></td><td className="td"><Link className="link" to={`/explorer?q=${encodeURIComponent(m.event_ids.slice(0, 40).map((i: number) => `id = ${i}`).join(' OR '))}`}>View evidence</Link></td></tr>))}</tbody></table>}</div>}
      {test && <div className="panel"><div className="panel-h">Sample-data test {test.available ? (test.passed ? <Pill tone="ok">passed</Pill> : <Pill tone="warn">failed</Pill>) : null}</div>
        <ul className="p-3 text-sm space-y-1">{!test.available ? <li className="text-mute">{test.message}</li> : test.checks.map((c: any) => <li key={c.description} className={c.passed ? 'text-emerald-300' : 'text-red-300'}>{c.passed ? '✓' : '✗'} {c.description}</li>)}</ul></div>}
    </div>
  )
}

export default function Rules() {
  const { data, error, loading, reload } = useFetch<any[]>('/api/rules')
  const ov = useFetch<any>('/api/overview')
  const { busy, run } = useAction()
  const [open, setOpen] = useState<string | null>(null)
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading && !data) return <Spinner />
  const hasData = !!ov.data?.has_data
  return (
    <div>
      <PageHeader title="Detection Rules" sub="Deterministic analytics. Each rule documents its logic, data requirements, false positives and limitations." />
      {ov.data && !hasData && <div className="mb-3"><NoData onLoaded={() => { ov.reload(); reload() }} /></div>}
      <div className="panel">
        {data?.map((r) => (
          <div key={r.id} className="border-b border-line-soft last:border-0">
            <div className="flex items-center gap-3 px-3 py-2.5 hover:bg-raised/50">
              <button className="flex-1 min-w-0 text-left flex items-center gap-3" aria-expanded={open === r.id} onClick={() => setOpen(open === r.id ? null : r.id)}>
                <span className="mono text-mute w-14 shrink-0">{r.id}</span><SevBadge sev={r.severity} />
                <span className="truncate"><span className="font-medium">{r.name}</span><span className="text-mute text-sm hidden md:inline"> — {r.description}</span></span>
              </button>
              <Link to={`/detections?rule_id=${r.id}`} className="link text-sm shrink-0">{r.detection_count} finding{r.detection_count === 1 ? '' : 's'}</Link>
              <label className="flex items-center gap-1.5 text-sm shrink-0 cursor-pointer"><input type="checkbox" checked={r.enabled} disabled={busy} onChange={(e) => run(async () => { await api(`/api/rules/${r.id}`, { method: 'PATCH', body: { enabled: e.target.checked } }); reload() }, e.target.checked ? 'Rule enabled' : 'Rule disabled')} />{r.enabled ? 'Enabled' : 'Disabled'}</label>
            </div>
            {open === r.id && <RuleDetail r={r} hasData={hasData} onChanged={reload} />}
          </div>))}
      </div>
    </div>
  )
}
