import { Link } from 'react-router-dom'
import type { Finding, FindingStatus } from '../types/finding'
import { SelfCheckBadge } from './SelfCheckBadge'
import { StatusBadge } from './StatusBadge'

const ALL_STATUSES: FindingStatus[] = [
  'raw',
  'mapped',
  'fix-proposed',
  'needs-human-only',
  'resolved',
]

interface FindingsTableProps {
  prId: string
  findings: Finding[]
  statusFilter: FindingStatus | 'all'
  onStatusFilterChange: (status: FindingStatus | 'all') => void
}

function formatLocation(finding: Finding): string {
  const [start, end] = finding.line_range ?? [null, null]
  if (start != null && end != null && start !== end) {
    return `${finding.file}:${start}-${end}`
  }
  if (start != null) {
    return `${finding.file}:${start}`
  }
  return finding.file
}

export function FindingsTable({
  prId,
  findings,
  statusFilter,
  onStatusFilterChange,
}: FindingsTableProps) {
  const filtered =
    statusFilter === 'all'
      ? findings
      : findings.filter((f) => f.status === statusFilter)

  return (
    <div className="findings-table-wrap">
      <div className="filter-bar">
        <label htmlFor="status-filter">Filter by status</label>
        <select
          id="status-filter"
          value={statusFilter}
          onChange={(e) => onStatusFilterChange(e.target.value as FindingStatus | 'all')}
        >
          <option value="all">All ({findings.length})</option>
          {ALL_STATUSES.map((s) => {
            const count = findings.filter((f) => f.status === s).length
            return (
              <option key={s} value={s} disabled={count === 0}>
                {s} ({count})
              </option>
            )
          })}
        </select>
      </div>

      {filtered.length === 0 ? (
        <p className="muted empty-state">No findings match this filter.</p>
      ) : (
        <table className="findings-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Rule</th>
              <th>Location</th>
              <th>Severity</th>
              <th>Self-check</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((finding) => (
              <tr key={finding.finding_id}>
                <td>
                  <StatusBadge status={finding.status} />
                </td>
                <td>
                  <Link
                    to={`/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(finding.finding_id)}`}
                    className="finding-link"
                  >
                    <span className="finding-link__source">{finding.source}</span>
                    <code className="finding-link__rule">{finding.rule_id}</code>
                  </Link>
                </td>
                <td>
                  <code>{formatLocation(finding)}</code>
                </td>
                <td>{finding.severity ?? '—'}</td>
                <td>
                  <SelfCheckBadge proposedFix={finding.proposed_fix} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
