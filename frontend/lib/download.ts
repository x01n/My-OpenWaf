export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = filename
    anchor.click()
  } finally {
    URL.revokeObjectURL(url)
  }
}

export function downloadTextFile(
  content: string,
  filename: string,
  type = "text/plain;charset=utf-8;"
) {
  downloadBlob(new Blob([content], { type }), filename)
}

export type CSVCell = string | number | boolean | null | undefined

export function toCSV(headers: CSVCell[], rows: CSVCell[][]) {
  return [
    headers.map(escapeCSVCell).join(","),
    ...rows.map((row) => row.map(escapeCSVCell).join(",")),
  ].join("\n")
}

export function downloadCSV(csv: string, name: string) {
  downloadTextFile(
    "\uFEFF" + csv,
    `${name}-${new Date().toISOString().slice(0, 10)}.csv`,
    "text/csv;charset=utf-8;"
  )
}

function escapeCSVCell(value: CSVCell) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`
}
