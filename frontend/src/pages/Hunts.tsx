import cytoscape from 'cytoscape'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { EntityLink, EventDrawer, EventTable, NoData, pivotQuery } from '../components'
import { Empty, ErrorBox, fmtTs, PageHeader, Pagination, Pill, Spinner, useAction, useFetch, useToast } from '../ui'

const TYPE_COLOR: Record<string, string> = { ip: '#4f9cf9', user: '#a78bfa', host: '#34d399', domain: '#fbbf24', process: '#f472b6' }

function Graph({ q, onPivot }: { q: string; onPivot: (query: string) => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const { data, error, loading, reload } = useFetch<any>('/api/graph', { q })
  const [sel, setSel] = useState<any>(null)
  useEffect(() => {
    if (!data || !ref.current || data.nodes.length === 0) return
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...data.nodes.map((n: any) => ({ data: { id: n.id, label: n.value, type: n.type, count: n.count } })),
        ...data.edges.map((e: any, i: number) => ({ data: { id: `e${i}`, source: e.source, target: e.target, label: e.label, count: e.count, event_ids: e.event_ids } })),
      ],
      style: [
        { selector: 'node', style: { 'background-color': (n: any) => TYPE_COLOR[n.data('type')] ?? '#888', label: 'data(label)', color: '#c8cdd6', 'font-size': 9, 'text-valign': 'bottom', 'text-margin-y': 3, width: 'mapData(count, 1, 40, 14, 34)', height: 'mapData(count, 1, 40, 14, 34)' } },
        { selector: 'edge', style: { width: 'mapData(count, 1, 20, 1, 4)', 'line-color': '#3a4152', 'target-arrow-color': '#3a4152', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier' } },
        { selector: ':selected', style: { 'border-width': 2, 'border-color': '#fff', 'line-color': '#4f9cf9', 'target-arrow-color': '#4f9cf9' } },
      ] as any,
      layout: { name: 'cose', animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70 } as any,
      wheelSensitivity: 0.3,
    })
    cy.on('tap', 'node', (e) => setSel({ kind: 'node', ...e.target.data() }))
    cy.on('tap', 'edge', (e) => setSel({ kind: 'edge', ...e.target.data() }))
    cy.on('tap', (e) => { if (e.target === cy) setSel(null) })
    return () => cy.destroy()
  }, [data])
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading && !data) return <Spinner label="Building graph" />
  if (!data || data.nodes.length === 0) return <Empty title="No relationships to show">The current search returns no events with linkable entities.</Empty>
  return (
    <div>
      <div className="flex flex-wrap gap-3 px-3 py-2 text-xs text-mute border-b border-line-soft">
        {Object.entries(TYPE_COLOR).map(([t, c]) => <span key={t} className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />{t}</span>)}
        <span className="ml-auto">{data.nodes.length} entities · {data.edges.length} relationships from {data.event_count} events{data.truncated ? ' (truncated — narrow the search)' : ''}</span>
      </div>
      <div className="grid lg:grid-cols-[1fr_18rem]">
        <div ref={ref} className="h-[28rem] bg-bg" role="img" aria-label="Entity relationship graph" />
        <div className="border-l border-line-soft p-3 text-sm space-y-2">
          {!sel && <p className="text-faint">Select an entity or relationship to see its supporting evidence. Edges are drawn only where events link the two entities.</p>}
          {sel?.kind === 'node' && <>
            <div className="text-xs uppercase text-mute">{sel.type}</div><div className="mono break-all">{sel.label}</div>
            <div className="text-mute">Appears in {sel.count} relationship observations</div>
            <button className="btn btn-sm btn-primary w-full" onClick={() => onPivot(sel.type === 'ip' ? `src_ip = "${sel.label}" OR dst_ip = "${sel.label}"` : pivotQuery({ user: 'username', host: 'hostname', domain: 'domain', process: 'process_name' }[sel.type as string] ?? 'message', sel.label))}>Pivot: search events</button>
            <EntityLink type={sel.type} value={sel.label} />
          </>}
          {sel?.kind === 'edge' && <>
            <div className="text-xs uppercase text-mute">Relationship</div><div>{sel.label}</div><div className="text-mute">{sel.count} supporting event(s)</div>
            <div className="mono text-xs break-all">{(sel.event_ids as number[]).map((id) => `EVT-${id}`).join(', ')}</div>
            <button className="btn btn-sm btn-primary w-full" onClick={() => onPivot((sel.event_ids as number[]).map((i) => `id = ${i}`).join(' OR '))}>Pivot: show these events</button>
          </>}
        </div>
      </div>
    </div>
  )
}

function HuntList() {
  const nav = useNavigate()
  const { data, error, loading, reload } = useFetch<any>('/api/hunts')
  const ov = useFetch<any>('/api/overview')
  const [title, setTitle] = useState('')
  const { busy, run } = useAction()
  const create = () => run(async () => { const h = await api('/api/hunts', { method: 'POST', body: { title: title.trim() } }); nav(`/hunts/${h.id}`) }, 'Hunt created')
  return (
    <div>
      <PageHeader title="Threat Hunting" sub="Form a hypothesis, search, pivot, collect evidence and conclude. Start from a detection, an event or from scratch." />
      <form className="panel p-3 mb-4 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (title.trim()) create() }}>
        <input className="input" aria-label="New hunt title" placeholder="New hunt title, e.g. Lateral movement from SRV-WEB01" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        <button className="btn btn-primary" disabled={busy || !title.trim()}>Start hunt</button>
      </form>
      {ov.data && !ov.data.has_data && <NoData onLoaded={() => { ov.reload(); reload() }} />}
      {error ? <ErrorBox message={error} onRetry={reload} /> : loading && !data ? <Spinner /> : data && (data.items.length === 0 ? <div className="panel"><Empty title="No hunts yet">Open a <Link className="link" to="/detections">detection</Link> and choose “Start hunt”, or create one above.</Empty></div> : (
        <div className="panel overflow-auto"><table className="w-full"><thead><tr><th className="th">ID</th><th className="th">Title</th><th className="th">Status</th><th className="th">Progress</th><th className="th">Source</th><th className="th">Case</th><th className="th">Updated</th></tr></thead>
          <tbody>{data.items.map((h: any) => (
            <tr key={h.id} className="cursor-pointer hover:bg-raised" tabIndex={0} onClick={() => nav(`/hunts/${h.id}`)} onKeyDown={(e) => e.key === 'Enter' && nav(`/hunts/${h.id}`)}>
              <td className="td mono text-mute">{h.id}</td><td className="td">{h.title}</td><td className="td"><Pill tone={h.status === 'concluded' ? 'ok' : 'accent'}>{h.status.replace('_', ' ')}</Pill></td>
              <td className="td text-mute">{h.progress_done}/{h.progress_total} steps</td><td className="td mono">{h.detection_id ?? '—'}</td><td className="td mono">{h.case_id ?? '—'}</td><td className="td mono">{fmtTs(h.updated_at)}</td></tr>))}</tbody></table></div>
      ))}
    </div>
  )
}

function Workspace({ id }: { id: string }) {
  const { data: h, error, loading, reload, setData } = useFetch<any>(`/api/hunts/${id}`)
  const toast = useToast()
  const nav = useNavigate()
  const { busy, run } = useAction()
  const [tab, setTab] = useState<'results' | 'graph'>('results')
  const [page, setPage] = useState(1)
  const [qDraft, setQDraft] = useState<string | null>(null)
  const [open, setOpen] = useState<number | null>(null)
  const [hyp, setHyp] = useState<string | null>(null)
  const [concl, setConcl] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const [kind, setKind] = useState<'note' | 'finding' | 'alternative'>('note')
  const results = useFetch<any>(h ? `/api/hunts/${id}/events` : null, { page, v: h?.query })

  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading && !h) return <Spinner />
  if (!h) return null
  const patch = (body: any, msg?: string) => run(async () => { const n = await api(`/api/hunts/${id}`, { method: 'PATCH', body }); setData(n); setPage(1) }, msg)
  const saved = new Set(h.items.filter((i: any) => i.kind === 'evidence').map((i: any) => Number(i.ref)))
  const applyQuery = (q: string) => { setQDraft(q); patch({ query: q }) }

  return (
    <div>
      <PageHeader crumbs={<Link className="link" to="/hunts">Hunts</Link>} title={`${h.id} · ${h.title}`}
        sub={h.detection_id ? <>Started from <Link className="link" to={`/detections/${h.detection_id}`}>{h.detection_id}</Link></> : undefined}
        actions={<>
          <select className="input !w-auto" aria-label="Hunt status" value={h.status} onChange={(e) => patch({ status: e.target.value }, 'Status updated')}><option value="open">open</option><option value="in_progress">in progress</option><option value="concluded">concluded</option></select>
          {h.case_id ? <Link className="btn" to={`/cases/${h.case_id}`}>Open {h.case_id}</Link> :
            <button className="btn btn-primary" disabled={busy} onClick={() => run(async () => { const r = await api(`/api/hunts/${id}/case`, { method: 'POST' }); nav(`/cases/${r.case_id}`) }, 'Case created from hunt')}>Create case from hunt</button>}
        </>} />
      <div className="grid xl:grid-cols-[1fr_22rem] gap-3">
        <div className="space-y-3 min-w-0">
          <div className="panel p-3">
            <label className="label" htmlFor="hyp">Hypothesis</label>
            <textarea id="hyp" className="input" rows={2} value={hyp ?? h.hypothesis} onChange={(e) => setHyp(e.target.value)} placeholder="What do you think happened, and what evidence would confirm or refute it?" maxLength={5000} />
            {hyp !== null && hyp !== h.hypothesis && <button className="btn btn-sm btn-primary mt-2" disabled={busy} onClick={() => patch({ hypothesis: hyp }, 'Hypothesis saved').then(() => setHyp(null))}>Save hypothesis</button>}
          </div>
          <div className="panel">
            <form className="flex gap-2 p-3" onSubmit={(e) => { e.preventDefault(); applyQuery(qDraft ?? h.query) }}>
              <input className="input mono" aria-label="Hunt search" value={qDraft ?? h.query} onChange={(e) => setQDraft(e.target.value)} placeholder='Search, e.g. username = "admin" OR src_ip = "203.0.113.45"' />
              <button className="btn btn-primary" disabled={busy}>Search</button>
            </form>
            <div className="flex gap-1 px-3 border-b border-line-soft text-sm">
              {(['results', 'graph'] as const).map((t) => <button key={t} className={`px-3 py-1.5 -mb-px border-b-2 ${tab === t ? 'border-accent text-ink' : 'border-transparent text-mute hover:text-ink'}`} onClick={() => setTab(t)}>{t === 'results' ? 'Events' : 'Relationship graph'}</button>)}
              {results.data && <span className="ml-auto text-xs text-mute self-center">{results.data.total.toLocaleString()} matching events</span>}
            </div>
            {tab === 'results' ? (results.error ? <div className="p-3"><ErrorBox message={results.error} /></div> : !results.data ? <Spinner /> : results.data.items.length === 0 ? <Empty title="No events">Define a search above to pull in events.</Empty> : <>
              <EventTable items={results.data.items} onOpen={setOpen} selected={open} compact />
              <Pagination page={results.data.page} pages={Math.max(1, Math.ceil(results.data.total / 50))} total={results.data.total} onPage={setPage} /></>)
              : <Graph q={h.query} onPivot={applyQuery} />}
          </div>
        </div>
        <div className="space-y-3">
          <div className="panel"><div className="panel-h">Progress</div>
            <ul className="p-3 space-y-1 text-sm">{h.progress.map((p: any) => <li key={p.step} className={p.done ? 'text-emerald-300' : 'text-mute'}>{p.done ? '✓' : '○'} {p.step}</li>)}</ul></div>
          <div className="panel"><div className="panel-h">Notes, findings &amp; alternatives</div>
            <div className="p-3 space-y-2">
              <div className="flex gap-2"><select className="input !w-auto" aria-label="Entry kind" value={kind} onChange={(e) => setKind(e.target.value as any)}><option value="note">Note</option><option value="finding">Finding</option><option value="alternative">Alternative explanation</option></select></div>
              <textarea className="input" rows={3} aria-label="Entry text" value={note} onChange={(e) => setNote(e.target.value)} maxLength={10000} placeholder="Record what you observed or considered" />
              <button className="btn btn-sm btn-primary" disabled={busy || !note.trim()} onClick={() => run(async () => { setData(await api(`/api/hunts/${id}/items`, { method: 'POST', body: { kind, body: note } })); setNote('') }, 'Saved')}>Add entry</button>
              <ul className="space-y-2 pt-1">
                {h.items.filter((i: any) => i.kind !== 'evidence').map((i: any) => (
                  <li key={i.id} className="text-sm border-l-2 border-line pl-2"><div className="flex justify-between"><Pill tone={i.kind === 'finding' ? 'ok' : i.kind === 'alternative' ? 'warn' : 'default'}>{i.kind}</Pill><span className="text-xs text-faint mono">{fmtTs(i.created_at).slice(5, 16)}</span></div><div className="mt-1 whitespace-pre-wrap">{i.body}</div></li>))}
              </ul>
            </div></div>
          <div className="panel"><div className="panel-h">Saved evidence ({saved.size})</div>
            <ul className="p-3 space-y-1.5 text-sm max-h-72 overflow-y-auto">
              {saved.size === 0 && <li className="text-faint">Open an event and choose “Save as evidence”, or use the button below on the open event.</li>}
              {h.items.filter((i: any) => i.kind === 'evidence').map((i: any) => <li key={i.id}><button className="link mono text-left" onClick={() => setOpen(Number(i.ref))}>EVT-{i.ref}</button> <span className="text-mute">{i.snapshot?.event_type} {i.snapshot?.username ?? ''} {i.body && `— ${i.body}`}</span></li>)}
            </ul></div>
          <div className="panel"><div className="panel-h">Conclusion</div><div className="p-3">
            <textarea className="input" rows={4} aria-label="Hunt Conclusion" value={concl ?? h.conclusion} onChange={(e) => setConcl(e.target.value)} placeholder="State what the evidence supports, and what it does not." maxLength={20000} />
            {concl !== null && concl !== h.conclusion && <button className="btn btn-sm btn-primary mt-2" disabled={busy} onClick={() => patch({ conclusion: concl, status: 'concluded' }, 'Conclusion saved').then(() => setConcl(null))}>Save conclusion &amp; mark concluded</button>}
          </div></div>
        </div>
      </div>
      <EventDrawer eventId={open} onClose={() => setOpen(null)} onPivot={(p) => { applyQuery(p); setOpen(null) }}
        extra={open != null && !saved.has(open) ? <button className="btn btn-sm" onClick={() => run(async () => { setData(await api(`/api/hunts/${id}/items`, { method: 'POST', body: { kind: 'evidence', event_id: open } })); toast('ok', 'Saved to hunt') })}>Save to this hunt</button> : undefined} />
    </div>
  )
}

export default function Hunts() {
  const { id } = useParams()
  return id ? <Workspace id={id} /> : <HuntList />
}
