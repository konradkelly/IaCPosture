import type { ControlMapping as ControlMappingType } from '../types/finding'

interface ControlMappingProps {
  mappings?: ControlMappingType[]
}

export function ControlMapping({ mappings }: ControlMappingProps) {
  if (!mappings?.length) {
    return <p className="muted">Not yet mapped to a framework control.</p>
  }

  return (
    <ul className="control-list">
      {mappings.map((m) => (
        <li key={`${m.framework}-${m.control_id}`} className="control-item">
          <div className="control-item__header">
            <span className="control-item__framework">{m.framework}</span>
            <code className="control-item__id">{m.control_id}</code>
          </div>
          {m.citation_span && (
            <blockquote className="control-item__citation">"{m.citation_span}"</blockquote>
          )}
          {m.rationale && <p className="control-item__rationale">{m.rationale}</p>}
        </li>
      ))}
    </ul>
  )
}
