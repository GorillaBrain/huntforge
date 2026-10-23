import { ReactNode, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from './api'
import { CopyButton, Drawer, Empty, ErrorBox, fmtTs, Modal, Pill, SevBadge, Spinner, useAction, useFetch, useToast } from './ui'

export function pivotQuery(field: string, value: string | number) {
  return `${field} = "${String(value).replace(/"/g, '\\"')}"`
}

/* ---------- load sample CTA ---------- */
export function LoadSample({ onLoaded }: { onLoaded?: () => void }) {
  const { busy, run } = useAction()
  return (
    <div className="flex items-center justify-center gap-2">
      <button className="btn btn-primary" disabled={busy} onClick={() => run(async () => { await api('/api/ingestion/sample', { method: 'POST' }); onLoaded?.() }, 'Sample dataset loaded and detections run')}>
        {busy ? 'Loading…' : 'Load synthetic sample dataset'}
      </button>
      <Link to="/data" className="btn">Upload logs</Link>
    </div>
  )
}

export function NoData({ onLoaded }: { onLoaded?: () => void }) {
  return (
    <div className="panel">
      <Empty title="No log data yet" action={<LoadSample onLoaded={onLoaded} />}>
        Upload JSON / NDJSON / sshd auth logs, or load the clearly-labelled synthetic sample dataset (simulated normal activity plus simulated suspicious behaviour).
      </Empty>
    </div>
  )
}

/* ---------- clickable entity value ---------- */
export function EntityLink({ type, value }: { type: 'ip' | 'user' | 'host' | 'domain' | 'process'; value?: string | null }) {
  if (!value) return <span className="text-faint">—</span>
  return <Link className="link mono" to={`/entities?type=${type}&value=${encodeURIComponent(value)}`}>{value}</Link>
}

/* ---------- add to case / hunt ---------- */
export function AddToDialog({ open, onClose, eventId, detectionId }: { open: boolean; onClose: () => void; eventId?: number; detectionId?: string }) {
  const nav = useNavigate()
  const cases = useFetch<any>(open ? '/api/cases' : null)
  const hunts = useFetch<any>(open ? '/api/hunts' : null)
  const { busy, run } = useAction()
  const [note, setNote] = useState('')
  const [title, setTitle] = useState('')
  const addCase = (cid: string) => run(async () => {
    await api(`/api/cases/${cid}/items`, { method: 'POST', body: detectionId ? { kind: 'detection', detection_id: detectionId } : { kind: 'evidence', event_id: eventId, body: note } })
    onClose()
  }, 'Added to case')
  const addHunt = (hid: string) => run(async () => {
    if (eventId == null) { nav(`/hunts/${hid}`); return }
    await api(`/api/hunts/${hid}/items`, { method: 'POST', body: { kind: 'evidence', event_id: eventId, body: note } })
    onClose()
  }, 'Evidence saved to hunt')
  const newCase = () => run(async () => {
    const c = await api('/api/cases', { method: 'POST', body: { title: title || (detectionId ? `Investigation of ${detectionId}` : `Investigation of EVT-${eventId}`), detection_id: detectionId, event_ids: eventId ? [eventId] : [] } })
    onClose(); nav(`/cases/${c.id}`)
  }, 'Case created')
  const newHunt = () => run(async () => {
    const h = await api('/api/hunts', { method: 'POST', body: { title: title || `Hunt from ${detectionId ?? 'EVT-' + eventId}`, detection_id: detectionId } })
    if (eventId != null) await api(`/api/hunts/${h.id}/items`, { method: 'POST', body: { kind: 'evidence', event_id: eventId, body: note } })
    onClose(); nav(`/hunts/${h.id}`)
  }, 'Hunt started')
  return (
    <Modal open={open} onClose={onClose} title={detectionId ? `Investigate ${detectionId}` : `Save EVT-${eventId} as evidence`}>
      <div className="space-y-3">
        {eventId != null && <div><label className="label" htmlFor="ev-note">Note (optional)</label><input id="ev-note" className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why is this relevant?" /></div>}
        <div><label className="label" htmlFor="new-title">Title for a new case or hunt</label><input id="new-title" className="input" value={title} onChange={(e) => setTitle(e.target.value)} /></div>
        <div className="flex gap-2"><button className="btn btn-primary" disabled={busy} onClick={newCase}>New case</button><button className="btn" disabled={busy} onClick={newHunt}>New hunt</button></div>
        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-line-soft">
          <div><div className="label">Existing cases</div>
            <ul className="space-y-1 max-h-40 overflow-y-auto">{(cases.data?.items ?? []).map((c: any) => <li key={c.id}><button disabled={busy} className="btn btn-sm w-full justify-start" onClick={() => addCase(c.id)}><span className="mono">{c.id}</span> <span className="truncate">{c.title}</span></button></li>)}
              {cases.data?.items?.length === 0 && <li className="text-xs text-faint">None yet</li>}</ul></div>
          <div><div className="label">Existing hunts</div>
            <ul className="space-y-1 max-h-40 overflow-y-auto">{(hunts.data?.items ?? []).map((h: any) => <li key={h.id}><button disabled={busy} className="btn btn-sm w-full justify-start" onClick={() => addHunt(h.id)}><span className="mono">{h.id}</span> <span className="truncate">{h.title}</span></button></li>)}
              {hunts.data?.items?.length === 0 && <li className="text-xs text-faint">None yet</li>}</ul></div>
        </div>
      </div>
    </Modal>
  )
}

/* ---------- event detail drawer ---------- */
const FIELD_ORDER: [string, string][] = [
  ['ref', 'Event ID'], ['ts', 'Timestamp (UTC)'], ['source', 'Source'], ['event_type', 'Event type'], ['outcome', 'Outcome'], ['severity', 'Severity'],
  ['username', 'User'], ['hostname', 'Host'], ['src_ip', 'Source IP'], ['dst_ip', 'Destination IP'], ['dst_port', 'Destination port'],
  ['process_name', 'Process'], ['parent_process', 'Parent process'], ['command_line', 'Command line'], ['domain', 'Domain'],
  ['bytes_out', 'Bytes out'], ['country', 'Country'], ['message', 'Message'], ['ingestion_id', 'Dataset #'],
]
const PIVOT: Record<string, string> = { username: 'username', hostname: 'hostname', src_ip: 'src_ip', dst_ip: 'dst_ip', domain: 'domain', process_name: 'process_name' }
const ENT: Record<string, string> = { username: 'user', hostname: 'host', src_ip: 'ip', dst_ip: 'ip', domain: 'domain', process_name: 'process' }

export function EventDrawer({ eventId, onClose, onPivot, extra }: { eventId: number | null; onClose: () => void; onPivot?: (q: string) => void; extra?: ReactNode }) {
  const { data, error, loading, reload } = useFetch<any>(eventId ? `/api/events/${eventId}` : null)
  const [adding, setAdding] = useState(false)
  let raw = ''
  if (data?.raw) { try { raw = JSON.stringify(JSON.parse(data.raw), null, 2) } catch { raw = data.raw } }
  return (
    <Drawer open={eventId != null} onClose={onClose} title={eventId ? `Event EVT-${eventId}` : ''} wide>
      {loading && <Spinner />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {data && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <button className="btn btn-sm btn-primary" onClick={() => setAdding(true)}>Save as evidence…</button>
            <button className="btn btn-sm" onClick={() => navigator.clipboard?.writeText(raw)}>Copy raw event</button>
            {extra}
          </div>
          {data.detections?.length > 0 && (
            <div className="text-sm"><span className="text-mute">Referenced by: </span>{data.detections.map((d: any) => <Link key={d.id} className="link mr-2" to={`/detections/${d.id}`}>{d.id}</Link>)}</div>
          )}
          <section>
            <h3 className="text-xs uppercase tracking-wide text-mute mb-1">Normalized fields</h3>
            <table className="w-full text-sm"><tbody>
              {FIELD_ORDER.filter(([k]) => data[k] !== null && data[k] !== undefined && data[k] !== '').map(([k, label]) => (
                <tr key={k} className="border-b border-line-soft">
                  <th className="text-left font-normal text-mute py-1 pr-3 w-40 align-top">{label}</th>
                  <td className="py-1 break-all">
                    <span className={k === 'severity' ? '' : 'mono'}>{k === 'severity' ? <SevBadge sev={data[k]} /> : String(data[k])}</span>
                    <CopyButton value={String(data[k])} />
                    {PIVOT[k] && <>
                      {onPivot && <button className="btn btn-ghost btn-sm !h-5 !px-1 text-faint hover:text-accent" title="Pivot: search events with this value" onClick={() => onPivot(pivotQuery(PIVOT[k], data[k]))}>⌕</button>}
                      <Link className="btn btn-ghost btn-sm !h-5 !px-1 text-faint hover:text-accent" title="Open entity page" to={`/entities?type=${ENT[k]}&value=${encodeURIComponent(data[k])}`}>◇</Link>
                    </>}
                  </td>
                </tr>
              ))}
            </tbody></table>
            <p className="text-xs text-faint mt-1">Fields not present in the source event are omitted rather than inferred.</p>
          </section>
          <section>
            <h3 className="text-xs uppercase tracking-wide text-mute mb-1">Original event</h3>
            <pre className="mono bg-bg border border-line rounded p-3 overflow-x-auto whitespace-pre-wrap break-all max-h-96">{raw}</pre>
          </section>
        </div>
      )}
      {adding && <AddToDialog open onClose={() => setAdding(false)} eventId={eventId!} />}
    </Drawer>
  )
}

/* ---------- event table ---------- */
export function EventTable({ items, onOpen, sort, order, onSort, selected, compact }: {
  items: any[]; onOpen: (id: number) => void; sort?: string; order?: string; onSort?: (col: string) => void; selected?: number | null; compact?: boolean
}) {
  const cols: [string, string][] = [['ts', 'Time (UTC)'], ['event_type', 'Type'], ['outcome', 'Outcome'], ['username', 'User'], ['hostname', 'Host'], ['src_ip', 'Source IP'], ['dst_ip', 'Dest'], ['details', 'Details']]
  const use = compact ? cols.filter(([k]) => !['dst_ip'].includes(k)) : cols
  return (
    <div className="overflow-auto">
      <table className="w-full min-w-[760px]">
        <thead><tr>
          {use.map(([k, l]) => {
            const sortable = onSort && ['ts', 'event_type', 'outcome', 'username', 'hostname', 'src_ip', 'dst_ip'].includes(k)
            return (
              <th key={k} className="th" aria-sort={sort === k ? (order === 'asc' ? 'ascending' : 'descending') : undefined}>
                {sortable ? <button className="hover:text-ink" onClick={() => onSort!(k)}>{l}{sort === k ? (order === 'asc' ? ' ▲' : ' ▼') : ''}</button> : l}
              </th>
            )
          })}
        </tr></thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.id} tabIndex={0} onClick={() => onOpen(e.id)} onKeyDown={(k) => k.key === 'Enter' && onOpen(e.id)}
              className={`cursor-pointer hover:bg-raised ${selected === e.id ? 'bg-accent-soft' : ''}`}>
              <td className="td mono whitespace-nowrap">{fmtTs(e.ts)}</td>
              <td className="td">{e.event_type ? <Pill>{e.event_type}</Pill> : '—'}</td>
              <td className={`td ${e.outcome === 'failure' ? 'text-red-300' : e.outcome === 'success' ? 'text-emerald-300' : 'text-mute'}`}>{e.outcome ?? '—'}</td>
              <td className="td mono">{e.username ?? '—'}</td>
              <td className="td mono">{e.hostname ?? '—'}</td>
              <td className="td mono">{e.src_ip ?? '—'}</td>
              {!compact && <td className="td mono">{e.dst_ip ? `${e.dst_ip}${e.dst_port ? ':' + e.dst_port : ''}` : '—'}</td>}
              <td className="td text-mute max-w-[28rem] truncate" title={e.command_line || e.message || e.domain || ''}>{e.command_line || e.message || e.domain || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function useCopyToast() {
  const t = useToast()
  return (v: string) => navigator.clipboard?.writeText(v).then(() => t('info', 'Copied'))
}
