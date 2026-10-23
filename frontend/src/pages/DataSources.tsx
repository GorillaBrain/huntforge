import { useRef, useState } from 'react'
import { api, apiUrl } from '../api'
import { Empty, ErrorBox, fmtTs, PageHeader, Pill, Spinner, download, useAction, useFetch } from '../ui'
import { LoadSample } from '../components'

export default function DataSources() {
  const { data, error, loading, reload } = useFetch<any>('/api/ingestion')
  const { busy, run } = useAction()
  const file = useRef<HTMLInputElement>(null)
  const [result, setResult] = useState<any>(null)
  const [err, setErr] = useState<string | null>(null)

  const upload = (f?: File) => {
    if (!f) return
    setResult(null); setErr(null)
    run(async () => {
      const form = new FormData(); form.append('file', f)
      try { setResult(await api('/api/ingestion/upload', { method: 'POST', form })); reload() } catch (e: any) { setErr(e.message); throw e }
    }, 'File ingested and detections run')
    if (file.current) file.current.value = ''
  }

  return (
    <div>
      <PageHeader title="Data Sources" sub="Ingest log files, load the synthetic sample, and manage datasets." />
      <div className="grid lg:grid-cols-2 gap-3 mb-4">
        <div className="panel p-4 space-y-3">
          <div className="text-sm font-medium">Upload a log file</div>
          <p className="text-sm text-mute">Supported: JSON array, newline-delimited JSON, and sshd authentication logs. Max {data?.max_upload_mb ?? 10} MB. Files are parsed as data only, never executed. Duplicate files are rejected.</p>
          <input ref={file} type="file" accept=".json,.jsonl,.ndjson,.log,.txt" className="hidden" id="up" onChange={(e) => upload(e.target.files?.[0])} />
          <label htmlFor="up" className={`btn btn-primary ${busy ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}`}>{busy ? 'Ingesting…' : 'Choose file…'}</label>
          {err && <div className="text-sm text-red-300 border border-red-900/60 rounded p-2" role="alert">Upload rejected: {err}<div className="text-xs text-mute mt-1">Existing data was not modified.</div></div>}
          {result && <div className="text-sm border border-line rounded p-2"><b>{result.filename}</b> ({result.format}): {result.stored_records} stored, {result.failed_records} failed.{result.detections && <> Detections: {result.detections.created} new.</>}
            {result.errors?.length > 0 && <ul className="mt-1 text-xs text-yellow-300 list-disc list-inside">{result.errors.map((e: string) => <li key={e}>{e}</li>)}</ul>}</div>}
        </div>
        <div className="panel p-4 space-y-3">
          <div className="text-sm font-medium">Synthetic sample dataset <Pill tone="warn">simulated</Pill></div>
          <p className="text-sm text-mute">Normal user activity plus simulated brute force, a compromised privileged account, suspicious processes, persistence and outbound traffic. Documentation IP ranges and reserved domains only. Not real telemetry.</p>
          <div className="flex flex-wrap gap-2"><LoadSample onLoaded={reload} />
            <button className="btn" onClick={() => download(apiUrl('/api/ingestion/sample/download'))}>Download sample file</button></div>
        </div>
      </div>
      {error ? <ErrorBox message={error} onRetry={reload} /> : loading && !data ? <Spinner /> : data && (
        <div className="panel"><div className="panel-h">Datasets</div>
          {data.items.length === 0 ? <Empty title="No datasets ingested" /> : <div className="overflow-auto"><table className="w-full"><thead><tr><th className="th">#</th><th className="th">File</th><th className="th">Format</th><th className="th">Stored</th><th className="th">Failed</th><th className="th">Ingested</th><th className="th" /></tr></thead>
            <tbody>{data.items.map((i: any) => <tr key={i.id}><td className="td mono">{i.id}</td><td className="td">{i.filename} {i.is_sample && <Pill tone="warn">synthetic</Pill>}</td><td className="td">{i.format}</td><td className="td tabular-nums">{i.stored_records.toLocaleString()}</td><td className="td tabular-nums">{i.failed_records}</td><td className="td mono">{fmtTs(i.created_at)}</td>
              <td className="td text-right"><button className="btn btn-sm btn-danger" disabled={busy} onClick={() => { if (confirm(`Delete dataset #${i.id}, its events and its detections? Case evidence copies are kept.`)) run(async () => { await api(`/api/ingestion/${i.id}`, { method: 'DELETE' }); reload() }, 'Dataset deleted') }}>Delete</button></td></tr>)}</tbody></table></div>}
        </div>)}
      <div className="panel mt-4 p-4 border-red-900/40"><div className="text-sm font-medium mb-1">Reset workspace</div>
        <p className="text-sm text-mute mb-2">Deletes all datasets, events, detections, hunts, cases, saved searches and rule settings. This cannot be undone.</p>
        <button className="btn btn-danger" disabled={busy} onClick={() => { if (prompt('Type RESET to wipe all data') === 'RESET') run(async () => { await api('/api/ingestion/reset', { method: 'POST', params: { confirm: 'RESET' } }); reload() }, 'Workspace reset') }}>Reset all data…</button></div>
    </div>
  )
}
