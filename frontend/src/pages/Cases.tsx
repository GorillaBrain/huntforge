import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { EventDrawer } from '../components'
import { Empty, ErrorBox, fmtTs, Modal, PageHeader, Pill, SEV_ORDER, SevBadge, Spinner, useAction, useFetch } from '../ui'

function CaseList() {
  const nav = useNavigate()
  const [status, setStatus] = useState('')
  const { data, error, loading, reload } = useFetch<any>('/api/cases', { status })
  const [creating, setCreating] = useState(false)
  const [f, setF] = useState({ title: '', description: '', severity: 'medium', assignee: '' })
  const { busy, run } = useAction()
  const create = () => run(async () => { const c = await api('/api/cases', { method: 'POST', body: { ...f, assignee: f.assignee || null } }); nav(`/cases/${c.id}`) }, 'Case created')
  return (
    <div>
      <PageHeader title="Investigation Cases" sub="Persistent records of evidence, notes, timeline and conclusions."
        actions={<><select className="input !w-auto" aria-label="Status filter" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All statuses</option><option value="open">open</option><option value="in_progress">in progress</option><option value="closed">closed</option></select>
          <button className="btn btn-primary" onClick={() => setCreating(true)}>New case</button></>} />
      {error ? <ErrorBox message={error} onRetry={reload} /> : loading && !data ? <Spinner /> : data && (data.items.length === 0 ? <div className="panel"><Empty title="No cases yet" action={<button className="btn btn-primary" onClick={() => setCreating(true)}>Create a case</button>}>Cases can also be created from a <Link className="link" to="/detections">detection</Link>, an event or a hunt.</Empty></div> : (
        <div className="panel overflow-auto"><table className="w-full"><thead><tr><th className="th">ID</th><th className="th">Title</th><th className="th">Severity</th><th className="th">Status</th><th className="th">Analyst</th><th className="th">Evidence</th><th className="th">Updated</th></tr></thead>
          <tbody>{data.items.map((c: any) => (
            <tr key={c.id} tabIndex={0} className="cursor-pointer hover:bg-raised" onClick={() => nav(`/cases/${c.id}`)} onKeyDown={(e) => e.key === 'Enter' && nav(`/cases/${c.id}`)}>
              <td className="td mono text-mute">{c.id}</td><td className="td">{c.title}</td><td className="td"><SevBadge sev={c.severity} /></td><td className="td"><Pill tone={c.status === 'closed' ? 'ok' : 'accent'}>{c.status.replace('_', ' ')}</Pill></td>
              <td className="td">{c.assignee ?? '—'}</td><td className="td tabular-nums">{c.item_counts.evidence ?? 0} events · {c.item_counts.detection ?? 0} detections</td><td className="td mono">{fmtTs(c.updated_at)}</td></tr>))}</tbody></table></div>))}
      <Modal open={creating} onClose={() => setCreating(false)} title="New case">
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); create() }}>
          <div><label className="label" htmlFor="ct">Title</label><input id="ct" className="input" required maxLength={200} value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></div>
          <div><label className="label" htmlFor="cd">Description</label><textarea id="cd" className="input" rows={3} maxLength={5000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
          <div className="grid grid-cols-2 gap-3"><div><label className="label" htmlFor="cs">Severity</label><select id="cs" className="input" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>{SEV_ORDER.map((s) => <option key={s}>{s}</option>)}</select></div>
            <div><label className="label" htmlFor="ca">Assigned analyst</label><input id="ca" className="input" maxLength={100} value={f.assignee} onChange={(e) => setF({ ...f, assignee: e.target.value })} /></div></div>
          <button className="btn btn-primary" disabled={busy || !f.title.trim()}>Create case</button>
        </form>
      </Modal>
    </div>
  )
}

function TextSection({ label, field, c, onSave, hint }: { label: string; field: string; c: any; onSave: (b: any, m?: string) => Promise<any>; hint?: string }) {
  const serverVal = c[field] ?? ''
  const [v, setV] = useState<string>(serverVal)
  useEffect(() => { setV(serverVal) }, [serverVal])
  const dirty = v !== serverVal
  return (
    <div className="panel"><div className="panel-h">{label}{dirty && <span className="text-yellow-300 normal-case font-normal">unsaved</span>}</div>
      <div className="p-3"><textarea className="input" rows={3} aria-label={`Case ${label}`} value={v} maxLength={20000} onChange={(e) => setV(e.target.value)} placeholder={hint} />
        <button className="btn btn-sm btn-primary mt-2" aria-label={`Save ${label}`} disabled={!dirty} onClick={() => onSave({ [field]: v }, `${label} saved`)}>Save {label}</button></div></div>
  )
}

function CaseDetail({ id }: { id: string }) {
  const nav = useNavigate()
  const { data: c, error, loading, reload, setData } = useFetch<any>(`/api/cases/${id}`)
  const { busy, run } = useAction()
  const [note, setNote] = useState('')
  const [open, setOpen] = useState<number | null>(null)
  const [meta, setMeta] = useState<any>(null)
  useEffect(() => { if (c) setMeta({ title: c.title, description: c.description, assignee: c.assignee ?? '' }) }, [c])
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading && !c) return <Spinner />
  if (!c || !meta) return null
  const patch = (body: any, msg?: string) => run(async () => setData(await api(`/api/cases/${id}`, { method: 'PATCH', body })), msg)
  const dets = c.items.filter((i: any) => i.kind === 'detection')
  const notes = c.items.filter((i: any) => i.kind === 'note')
  const ev = c.items.filter((i: any) => i.kind === 'evidence')
  const metaDirty = meta.title !== c.title || meta.description !== c.description || meta.assignee !== (c.assignee ?? '')
  return (
    <div>
      <PageHeader crumbs={<Link className="link" to="/cases">Cases</Link>} title={`${c.id} · ${c.title}`} sub={`Created ${fmtTs(c.created_at)} · updated ${fmtTs(c.updated_at)}`}
        actions={<>
          <select className="input !w-auto" aria-label="Severity" value={c.severity} onChange={(e) => patch({ severity: e.target.value }, 'Severity updated')}>{SEV_ORDER.map((s) => <option key={s}>{s}</option>)}</select>
          <select className="input !w-auto" aria-label="Status" value={c.status} onChange={(e) => patch({ status: e.target.value }, 'Status updated')}><option value="open">open</option><option value="in_progress">in progress</option><option value="closed">closed</option></select>
          <Link className="btn btn-primary" to={`/reports/${c.id}`}>Generate report</Link>
          <button className="btn btn-danger" onClick={() => { if (confirm(`Delete ${c.id}? Evidence copies in this case will be lost.`)) run(async () => { await api(`/api/cases/${id}`, { method: 'DELETE' }); nav('/cases') }, 'Case deleted') }}>Delete</button></>} />
      <div className="grid xl:grid-cols-[1fr_24rem] gap-3">
        <div className="space-y-3 min-w-0">
          <div className="panel p-3 grid md:grid-cols-2 gap-3">
            <div><label className="label" htmlFor="t">Title</label><input id="t" className="input" maxLength={200} value={meta.title} onChange={(e) => setMeta({ ...meta, title: e.target.value })} /></div>
            <div><label className="label" htmlFor="a">Assigned analyst</label><input id="a" className="input" maxLength={100} value={meta.assignee} onChange={(e) => setMeta({ ...meta, assignee: e.target.value })} /></div>
            <div className="md:col-span-2"><label className="label" htmlFor="d">Description</label><textarea id="d" className="input" rows={2} maxLength={5000} value={meta.description} onChange={(e) => setMeta({ ...meta, description: e.target.value })} /></div>
            {metaDirty && <div><button className="btn btn-sm btn-primary" disabled={busy || !meta.title.trim()} onClick={() => patch({ title: meta.title, description: meta.description, assignee: meta.assignee || null }, 'Case details saved')}>Save details</button></div>}
          </div>
          <div className="panel"><div className="panel-h">Related detections ({dets.length})</div>
            {dets.length === 0 ? <p className="p-3 text-sm text-faint">No detections attached.</p> : <ul>{dets.map((d: any) => (
              <li key={d.id} className="px-3 py-2 border-b border-line-soft last:border-0 text-sm flex items-center gap-2"><SevBadge sev={d.snapshot.severity} /><Link className="link mono" to={`/detections/${d.ref}`}>{d.ref}</Link><span className="truncate">{d.body}</span></li>))}</ul>}</div>
          <div className="panel"><div className="panel-h">Investigation timeline (event time)</div>
            {c.timeline.length === 0 ? <p className="p-3 text-sm text-faint">Add evidence events to build a timeline.</p> :
              <ol className="p-3 space-y-2 border-l border-line ml-3">{c.timeline.map((t: any) => (
                <li key={t.ref} className="relative pl-4 text-sm"><span className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-accent" /><button className="mono text-faint hover:text-accent" onClick={() => setOpen(Number(t.ref.replace('EVT-', '')))}>{fmtTs(t.ts)} · {t.ref}</button><div>{t.summary}</div>{t.note && <div className="text-mute text-xs">Note: {t.note}</div>}</li>))}</ol>}</div>
          <div className="panel"><div className="panel-h">Evidence ({ev.length}) <span className="normal-case font-normal text-faint">snapshots taken when collected</span></div>
            {ev.length === 0 ? <p className="p-3 text-sm text-faint">No evidence collected. Save events from the Log Explorer or a detection.</p> : (
              <div className="overflow-auto max-h-80"><table className="w-full"><tbody>{ev.map((i: any) => (
                <tr key={i.id} className="hover:bg-raised"><td className="td mono"><button className="link" onClick={() => setOpen(Number(i.ref))}>EVT-{i.ref}</button></td><td className="td mono whitespace-nowrap">{fmtTs(i.snapshot?.ts)}</td><td className="td">{i.snapshot?.event_type} {i.snapshot?.username ?? ''} {i.snapshot?.src_ip ?? ''}</td><td className="td text-mute">{i.body}</td>
                  <td className="td"><button className="btn btn-ghost btn-sm" aria-label={`Remove EVT-${i.ref}`} onClick={() => run(async () => { await api(`/api/cases/${id}/items/${i.id}`, { method: 'DELETE' }); reload() }, 'Evidence removed')}>✕</button></td></tr>))}</tbody></table></div>)}</div>
          <TextSection label="Findings" field="findings" c={c} onSave={patch} hint="What did the investigation establish?" />
          <TextSection label="Conclusion" field="conclusion" c={c} onSave={patch} hint="What do the evidence and analysis support?" />
          <TextSection label="Remaining uncertainty" field="uncertainty" c={c} onSave={patch} hint="What is still unknown or unverified?" />
          <TextSection label="Recommendations" field="recommendations" c={c} onSave={patch} hint="Containment, remediation, detection improvements" />
        </div>
        <div className="space-y-3">
          <div className="panel"><div className="panel-h">Analyst notes ({notes.length})</div><div className="p-3 space-y-2">
            <textarea className="input" rows={3} aria-label="New note" maxLength={10000} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Record an action or observation" />
            <button className="btn btn-sm btn-primary" disabled={busy || !note.trim()} onClick={() => run(async () => { setData(await api(`/api/cases/${id}/items`, { method: 'POST', body: { kind: 'note', body: note } })); setNote('') }, 'Note added')}>Add note</button>
            <ul className="space-y-2 pt-1">{[...notes].reverse().map((n: any) => (<li key={n.id} className="text-sm border-l-2 border-line pl-2"><div className="text-xs text-faint mono">{fmtTs(n.created_at)}</div><div className="whitespace-pre-wrap">{n.body}</div></li>))}</ul></div></div>
          {c.hunts.length > 0 && <div className="panel"><div className="panel-h">Linked hunts</div><ul className="p-3 text-sm space-y-1">{c.hunts.map((h: any) => <li key={h.id}><Link className="link" to={`/hunts/${h.id}`}>{h.id}</Link> {h.title}</li>)}</ul></div>}
        </div>
      </div>
      <EventDrawer eventId={open} onClose={() => setOpen(null)} />
    </div>
  )
}

export default function Cases() {
  const { id } = useParams()
  return id ? <CaseDetail id={id} /> : <CaseList />
}
