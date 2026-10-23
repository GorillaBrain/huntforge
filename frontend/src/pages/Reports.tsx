import { Link, useNavigate, useParams } from 'react-router-dom'
import { apiUrl } from '../api'
import { Empty, ErrorBox, fmtTs, PageHeader, Pill, SevBadge, Spinner, download, useFetch } from '../ui'

export default function Reports() {
  const { id } = useParams()
  const nav = useNavigate()
  const list = useFetch<any>('/api/cases')
  const report = useFetch<any>(id ? `/api/reports/cases/${id}` : null)
  if (!id) {
    return (
      <div>
        <PageHeader title="Reports" sub="Reports are generated from the real case record: evidence snapshots, detections, notes and your conclusion." />
        {list.error ? <ErrorBox message={list.error} onRetry={list.reload} /> : !list.data ? <Spinner /> : list.data.items.length === 0 ? <div className="panel"><Empty title="No cases to report on">Create a case from a <Link className="link" to="/detections">detection</Link> first.</Empty></div> : (
          <div className="panel overflow-auto"><table className="w-full"><thead><tr><th className="th">Case</th><th className="th">Title</th><th className="th">Severity</th><th className="th">Status</th><th className="th">Evidence</th><th className="th" /></tr></thead>
            <tbody>{list.data.items.map((c: any) => <tr key={c.id} className="hover:bg-raised"><td className="td mono">{c.id}</td><td className="td">{c.title}</td><td className="td"><SevBadge sev={c.severity} /></td><td className="td"><Pill>{c.status}</Pill></td><td className="td">{c.item_counts.evidence ?? 0}</td><td className="td"><button className="btn btn-sm" onClick={() => nav(`/reports/${c.id}`)}>Open report</button></td></tr>)}</tbody></table></div>)}
      </div>
    )
  }
  const html = apiUrl(`/api/reports/cases/${id}`, { format: 'html' })
  return (
    <div>
      <PageHeader crumbs={<Link className="link" to="/reports">Reports</Link>} title={`Report · ${id}`} sub={report.data ? `Generated ${fmtTs(report.data.generated_at)} from current case data` : undefined}
        actions={<>
          <Link className="btn" to={`/cases/${id}`}>Back to case</Link>
          <button className="btn" onClick={() => download(apiUrl(`/api/reports/cases/${id}`, { format: 'markdown' }))}>Download Markdown</button>
          <button className="btn btn-primary" onClick={() => window.open(html, '_blank', 'noopener')}>Open printable HTML</button></>} />
      {report.error ? <ErrorBox message={report.error} onRetry={report.reload} /> : !report.data ? <Spinner /> : (
        <div className="panel overflow-hidden">
          <iframe title="Report preview" src={html} sandbox="" className="w-full h-[75vh] bg-white" />
        </div>)}
      <p className="text-xs text-faint mt-2">Preview is sandboxed and rendered by the server with every dynamic value HTML-escaped. Use the browser’s print dialog on the printable page to save as PDF.</p>
    </div>
  )
}
