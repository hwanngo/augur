/**
 * Client-side CSV export (RFC 4180).
 * - Fields are quoted iff they contain `"`, `,`, `\n` or `\r`; embedded `"` is doubled.
 * - Rows joined with CRLF line endings, header row first.
 * - `downloadCsv` writes a UTF-8 Blob with a leading BOM so spreadsheets (Excel)
 *   render non-ASCII (e.g. Vietnamese) accents correctly.
 * No dependencies.
 */

export interface CsvColumn<T> {
  header: string;
  value: (row: T) => string | number;
}

const NEEDS_QUOTING = /[",\n\r]/;
// Spreadsheet formula-injection vectors: a leading =, +, -, @, tab or CR makes
// Excel/Sheets evaluate the cell as a formula. Neutralize by prefixing a single
// quote before the value (then apply normal RFC-4180 quoting on top).
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

function escapeField(raw: string | number): string {
  let s = String(raw);
  // Only string values can carry a formula-injection payload; a real number
  // (e.g. a negative proximity delta like -0.5) is never a formula and must
  // stay numeric so spreadsheets can sum/sort the column.
  if (typeof raw === 'string' && FORMULA_PREFIX.test(s)) {
    s = `'${s}`;
  }
  if (NEEDS_QUOTING.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function toCsv<T>(rows: T[], columns: CsvColumn<T>[]): string {
  const header = columns.map((c) => escapeField(c.header)).join(',');
  const body = rows.map((row) =>
    columns.map((c) => escapeField(c.value(row))).join(',')
  );
  return [header, ...body].join('\r\n');
}

export function downloadCsv(filename: string, csv: string): void {
  const BOM = '﻿';
  const blob = new Blob([BOM + csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Local-clock date stamp (YYYY-MM-DD) for export filenames. */
export function dateStamp(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** Client-side JSON download (no BOM); mirrors downloadCsv. */
export function downloadJson(filename: string, obj: unknown): void {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Client-side text download with an arbitrary mime (e.g. YAML); mirrors downloadJson. */
export function downloadText(filename: string, text: string, mime = 'text/plain'): void {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
