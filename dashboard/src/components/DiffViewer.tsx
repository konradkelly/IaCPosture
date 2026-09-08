interface DiffViewerProps {
  diff?: string
  fileName?: string
}

/** Renders a unified diff with simple +/- line highlighting. */
export function DiffViewer({ diff, fileName }: DiffViewerProps) {
  if (!diff?.trim()) {
    return <p className="muted">No diff available for this finding.</p>
  }

  const lines = diff.split('\n')

  return (
    <div className="diff-viewer">
      {fileName && <div className="diff-viewer__file">{fileName}</div>}
      <pre className="diff-viewer__pre">
        {lines.map((line, i) => {
          let className = 'diff-line'
          if (line.startsWith('+++') || line.startsWith('---')) {
            className += ' diff-line--meta'
          } else if (line.startsWith('@@')) {
            className += ' diff-line--hunk'
          } else if (line.startsWith('+')) {
            className += ' diff-line--add'
          } else if (line.startsWith('-')) {
            className += ' diff-line--remove'
          }
          return (
            <span key={i} className={className}>
              {line}
              {'\n'}
            </span>
          )
        })}
      </pre>
    </div>
  )
}
