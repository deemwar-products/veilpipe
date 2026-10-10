// Read-only: did an opencode store rewrite by audit --opencode --fix before 2aa08d2 change any NUMBER values?
// The rewrite took a JSON cell holding a secret through JSON.parse/JSON.stringify. That rounded integers
// over 2^53 and reformatted others (1.0 -> 1). Run it on a PRE-fix copy of the store (the backup): for every content
// cell the fix would rewrite, it counts cells whose formatting changed and cells holding an integer
// over 2^53 (a changed value). Counts per table.column only; it prints no value and never writes.
//   node bench/fix-number-impact.ts <pre-fix opencode.db> [--patterns <file>]
// Speed (Linux, 10-09): a 419 MB store with 100k cells in 16.8 s, 111 MB RAM, so about 1-2 min for a 1.8 GB store.
import { createRequire } from 'node:module'
import { compile } from '../hooks/core.ts'
import { load } from '../cli/veilpipe.ts'
import { CONTENT_COLUMNS, redactCell } from '../opencode/store.ts'

const path = process.argv[2]
if (!path) {
  console.error('usage: node bench/fix-number-impact.ts <pre-fix opencode.db> [--patterns <file>]')
  process.exit(2)
}
const pi = process.argv.indexOf('--patterns')
const compiled = compile(load({ patterns: pi > 0 ? process.argv[pi + 1] : undefined }))
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite')
const db = new DatabaseSync(path, { readOnly: true })
const tables = new Set(db.prepare("select name from sqlite_master where type='table'").all().map((r: any) => r.name))
const q = (id: string) => `"${id.replace(/"/g, '""')}"`

// Integers whose source text a double cannot hold: the old rewrite changed their value.
function unsafeInts(raw: string): number {
  let n = 0
  ;(JSON.parse as any)(raw, (_k: string, v: unknown, c?: { source?: string }) => {
    if (typeof v === 'number' && c?.source && /^-?\d+$/.test(c.source) && !Number.isSafeInteger(Number(c.source))) n++
    return v
  })
  return n
}

let total = { rewritten: 0, reformatted: 0, valueChanged: 0 }
for (const [t, c] of CONTENT_COLUMNS) {
  if (!tables.has(t)) continue
  if (!db.prepare(`pragma table_info(${q(t)})`).all().some((x: any) => x.name === c)) continue
  const row = { rewritten: 0, reformatted: 0, valueChanged: 0 }
  for (const r of db.prepare(`select ${q(c)} as v from ${q(t)} where ${q(c)} is not null`).iterate()) {
    const raw = String(r.v)
    if (redactCell(raw, compiled, new Map()) === undefined) continue // held no secret: the fix never touched it
    row.rewritten++
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      continue // plain text cell: rewritten as text, no numbers involved
    }
    if (JSON.stringify(parsed) !== raw) row.reformatted++
    if (unsafeInts(raw) > 0) row.valueChanged++
  }
  if (row.rewritten) console.log(`${t}.${c}: ${row.rewritten} cell(s) rewritten by --fix · ${row.reformatted} reformatted · ${row.valueChanged} with a changed number value`)
  for (const k of Object.keys(total) as (keyof typeof total)[]) total[k] += row[k]
}
console.log(`total: ${total.rewritten} rewritten · ${total.reformatted} reformatted · ${total.valueChanged} with a changed number value${total.valueChanged ? ' (restore those cells from this backup)' : ''}`)
db.close()
process.exit(total.valueChanged ? 1 : 0)
