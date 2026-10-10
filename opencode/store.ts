// opencode keeps sessions in SQLite (<data>/opencode/opencode.db: event, part, message, session... tables of JSON text).
// Shared by the plugin (bun:sqlite, live: values already replaced this session) and `veilpipe audit --opencode`
// (node:sqlite: values found by the patterns). Both drivers expose prepare(sql).all/.run and exec.
import { closeSync, openSync, readdirSync, readSync, statSync, writeSync } from 'node:fs'
import { deepMap, parseLossless, redact, scan } from '../hooks/core.ts'
import type { Compiled } from '../hooks/core.ts'

export type Db = {
  prepare(sql: string): { all(...p: unknown[]): any[]; run(...p: unknown[]): { changes: number | bigint }; iterate?(...p: unknown[]): Iterable<any> }
  exec(sql: string): unknown
}

// The TUI client writes what the person types to these files BEFORE the server (and any plugin) sees the message.
export const STATE_FILES = ['prompt-history.jsonl', 'prompt-stash.jsonl', 'kv.json', 'session.json']
export function stateDir(env: Record<string, string | undefined> = process.env): string {
  return `${env.XDG_STATE_HOME ?? `${env.HOME}/.local/state`}/opencode`
}

export function dataDir(env: Record<string, string | undefined> = process.env): string {
  return `${env.XDG_DATA_HOME ?? `${env.HOME}/.local/share`}/opencode`
}

export function storePath(env: Record<string, string | undefined> = process.env): string {
  return env.OPENCODE_DB ?? `${dataDir(env)}/opencode.db`
}

// opencode 2.x also keeps text outside the db (2.0.22, 10-08): every shell command's raw output (shell/<project>/sh_<id>.out)
// and its logs, where the CLI records its own argv (`opencode run "<prompt>"`) before any plugin is loaded.
export const V2_FILE_DIRS = ['shell', 'log']

// Regular files under dir (recursive) modified at or after sinceMs; [] if dir does not exist.
export function recentFiles(dir: string, sinceMs: number): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    let entries: import('node:fs').Dirent[]
    try {
      entries = readdirSync(d, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const p = `${d}/${e.name}`
      if (e.isDirectory()) walk(p)
      else if (e.isFile()) {
        try {
          if (statSync(p).mtimeMs >= sinceMs) out.push(p)
        } catch {}
      }
    }
  }
  walk(dir)
  return out
}

// Conversation content only. Never ids/keys (rewriting them broke a foreign key on a real store, 10-06), and never
// opencode's OWN secrets: account/control_account tokens, credential.value, session_share.secret are its login and
// connector store, not model context; replacing them would log the person out and break integrations.
export const CONTENT_COLUMNS: [string, string][] = [
  ['event', 'data'], ['message', 'data'], ['part', 'data'], ['session_message', 'data'], ['session_input', 'prompt'],
  ['session', 'title'], ['session', 'summary_diffs'], ['todo', 'content'],
  ['session_context_epoch', 'baseline'], ['session_context_epoch', 'snapshot'],
  // opencode 2.x (2.0.22): sessions moved to session_v2, whose title is generated from the prompt (an unprotected
  // session's title held the raw key, 10-08); queued prompts sit in session_inbox / session_pending.
  ['session_v2', 'title'], ['session_v2', 'summary_diffs'], ['session_inbox', 'payload'], ['session_pending', 'data'],
]

// How each content table names its session (all indexed in 1.18): the live scrub touches only the current session's
// rows; a whole-store pass per tool call held the write lock 3-8 s on a 524 MB store (10-06).
export const SESSION_KEY: Record<string, string> = {
  event: 'aggregate_id', message: 'session_id', part: 'session_id', session_message: 'session_id', session_input: 'session_id',
  todo: 'session_id', session_context_epoch: 'session_id', session: 'id',
  session_v2: 'id', session_inbox: 'session_id', session_pending: 'session_id',
}

// The allowlisted columns this store has, minus any that are (part of) a primary or foreign key in this version.
function contentColumns(db: Db): [string, string][] {
  const tables = new Set(db.prepare("select name from sqlite_master where type='table'").all().map((r: any) => r.name))
  return CONTENT_COLUMNS.filter(([t, c]) => {
    if (!tables.has(t)) return false
    const col = db.prepare(`pragma table_info(${q(t)})`).all().find((x: any) => x.name === c)
    const fk = db.prepare(`pragma foreign_key_list(${q(t)})`).all().some((f: any) => f.from === c)
    return !!col && String(col.type).toUpperCase() === 'TEXT' && !col.pk && !fk
  })
}

const q = (id: string) => `"${id.replace(/"/g, '""')}"`

// A value appears raw in plain columns and JSON-escaped inside JSON text; replace both forms.
function forms(value: string): string[] {
  const esc = JSON.stringify(value).slice(1, -1)
  return esc === value ? [value] : [value, esc]
}

// Replace every known value (value -> NAME) with $NAME in the content columns, in ONE transaction (all or nothing).
// Longest value first: replacing a value that is part of a longer one first would leave fragments that match anew.
// `verify` runs inside the transaction; returning a reason rolls everything back.
export function scrubStore(db: Db, known: Map<string, string>, verify?: () => string | undefined, sessionID?: string): number {
  if (known.size === 0) return 0
  let changed = 0
  db.exec('pragma busy_timeout = 3000')
  // Zero the bytes an update frees; otherwise the old value can survive in page slack.
  db.exec('pragma secure_delete = ON')
  const ordered = [...known].sort((a, b) => b[0].length - a[0].length)
  db.exec('begin immediate')
  try {
    for (const [t, c] of contentColumns(db)) {
      const scope = sessionID && SESSION_KEY[t] ? ` and ${q(SESSION_KEY[t]!)} = ?` : ''
      for (const [value, name] of ordered)
        for (const f of forms(value)) {
          const args = scope ? [f, `$${name}`, f, sessionID] : [f, `$${name}`, f]
          changed += Number(db.prepare(`update ${q(t)} set ${q(c)} = replace(${q(c)}, ?, ?) where instr(${q(c)}, ?) > 0${scope}`).run(...args).changes)
        }
    }
    const why = verify?.()
    if (why) throw new Error(`rolled back: ${why}`)
    db.exec('commit')
  } catch (err) {
    db.exec('rollback')
    throw err
  }
  if (changed > 0) {
    try {
      db.exec('pragma wal_checkpoint(TRUNCATE)')
    } catch {
      // A busy reader keeps the WAL; the next checkpoint folds it.
    }
  }
  return changed
}

// Find secret-shaped values in the content columns (for audit): value -> NAME, plus how many cells hold one.
export function findInStore(db: Db, compiled: Compiled[]): { found: Map<string, string>; cells: number } {
  const found = new Map<string, string>()
  let cells = 0
  for (const [t, c] of contentColumns(db)) {
    // Row by row: a 1.7 GB store read with .all() held whole tables in memory (524 MB store: 745 MB RSS).
    const st = db.prepare(`select ${q(c)} as v from ${q(t)} where ${q(c)} is not null`)
    for (const row of st.iterate ? st.iterate() : st.all()) {
      // JSON cells are scanned string by string: in raw JSON a "\n" is two characters and would join lines.
      const strings: string[] = []
      try {
        deepMap(JSON.parse(String(row.v)), s => (strings.push(s), s))
      } catch {
        strings.push(String(row.v))
      }
      const hits = strings.flatMap(s => scan(s, compiled)).filter(h => h.name !== 'EMAIL')
      if (hits.length > 0) cells++
      for (const h of hits) if (!found.has(h.value)) found.set(h.value, h.name)
    }
  }
  return { found, cells }
}

// One cell through the same redact() the live hooks use (which repeats until stable), string by string for JSON.
// Returns the new text, or undefined if unchanged.
export function redactCell(raw: string, compiled: Compiled[], known: Map<string, string>): string | undefined {
  const once = (s: string) => redact(s, compiled, known).text
  let out: string
  try {
    out = JSON.stringify(deepMap(parseLossless(raw), once))
    if (out === JSON.stringify(parseLossless(raw))) return undefined
  } catch {
    out = once(raw)
    if (out === raw) return undefined
  }
  return out
}

const hitsIn = (raw: string, compiled: Compiled[]) => {
  const strings: string[] = []
  try {
    deepMap(JSON.parse(raw), s => (strings.push(s), s))
  } catch {
    strings.push(raw)
  }
  return strings.flatMap(s => scan(s, compiled)).filter(h => h.name !== 'EMAIL')
}

// --fix for audit: every content cell through redactCell, written in ONE transaction. Cells that did not change had no
// hit, so only the rewritten cells are re-checked; any remaining hit (or any error) rolls everything back.
function pendingUpdates(db: Db, compiled: Compiled[]) {
  const known = new Map<string, string>()
  const updates: [string, string, unknown, string][] = []
  let before = 0
  for (const [t, c] of contentColumns(db)) {
    const st = db.prepare(`select rowid as r, ${q(c)} as v from ${q(t)} where ${q(c)} is not null`)
    for (const row of st.iterate ? st.iterate() : st.all()) {
      const raw = String(row.v)
      const next = redactCell(raw, compiled, known)
      if (next === undefined) continue
      before += new Set(hitsIn(raw, compiled).map(h => h.value)).size
      updates.push([t, c, row.r, next])
    }
  }
  return { updates, before }
}

// The dry run of fixStore: exactly which table.column cells it would rewrite (rows per column), writing nothing.
export function planStore(db: Db, compiled: Compiled[]): { table: string; column: string; rows: number }[] {
  const by = new Map<string, number>()
  for (const [t, c] of pendingUpdates(db, compiled).updates) by.set(`${t}\0${c}`, (by.get(`${t}\0${c}`) ?? 0) + 1)
  return [...by].map(([k, rows]) => ({ table: k.split('\0')[0]!, column: k.split('\0')[1]!, rows }))
}

// A consistent snapshot of the whole store (WAL included) taken BEFORE --fix writes anything.
export function backupStore(db: Db, to: string) {
  db.exec(`vacuum into '${to.replace(/'/g, "''")}'`)
}

export function fixStore(db: Db, compiled: Compiled[]): { before: number; after: number; changed: number } {
  const { updates, before } = pendingUpdates(db, compiled)
  if (updates.length === 0) return { before: 0, after: 0, changed: 0 }
  db.exec('pragma busy_timeout = 3000')
  db.exec('pragma secure_delete = ON')
  db.exec('begin immediate')
  let after = 0
  try {
    for (const [t, c, r, v] of updates) db.prepare(`update ${q(t)} set ${q(c)} = ? where rowid = ?`).run(v, r)
    for (const [t, c, r] of updates) {
      const row = db.prepare(`select ${q(c)} as v from ${q(t)} where rowid = ?`).all(r)[0]
      after += hitsIn(String(row?.v ?? ''), compiled).length
    }
    if (after > 0) throw new Error(`rolled back: ${after} matches remain in rewritten cells`)
    db.exec('commit')
  } catch (err) {
    db.exec('rollback')
    throw err
  }
  try {
    db.exec('pragma wal_checkpoint(TRUNCATE)')
  } catch {}
  return { before, after, changed: updates.length }
}

// Offline only (opencode closed): rewrite the whole file so no stale page keeps an old value.
export function compactStore(db: Db) {
  db.exec('pragma wal_checkpoint(TRUNCATE)')
  db.exec('vacuum')
}

// Files other processes keep appending to (opencode's log: the CLI, the service and every `opencode service ...` call
// write to one file). A rewrite (read, replace, write back) must re-check the file is unchanged, and on a busy log it
// gives up ('busy'), or loses lines appended mid-rewrite (10-08: on one macOS machine the CLI's argv line stayed raw while a
// quieter Linux log was rewritten fine). Instead each raw value is overwritten IN PLACE with a mask of the same byte
// length ($NAME then '*'), so the file never changes size and concurrent appends are untouched. Returns how many
// copies were masked. Files over maxBytes are skipped (-1).
// `from` scans only from that byte offset (a watcher that already masked everything before it); the caller keeps
// some overlap so a value split across two writes is still found.
export function maskInPlace(path: string, known: Map<string, string>, maxBytes = 64 * 1024 * 1024, from = 0): number {
  const end = statSync(path).size
  const start = Math.min(Math.max(0, from), end)
  if (end - start > maxBytes) return -1
  const fd = openSync(path, 'r+')
  try {
    const size = end - start
    const buf = Buffer.alloc(size)
    let got = 0
    while (got < size) {
      const n = readSync(fd, buf, got, size - got, start + got)
      if (n <= 0) break
      got += n
    }
    let masked = 0
    const ordered = [...known].sort((a, b) => b[0].length - a[0].length)
    for (const [value, name] of ordered)
      for (const form of forms(value)) {
        const raw = Buffer.from(form)
        const label = Buffer.from(`$${name}`)
        const mask = label.length <= raw.length ? Buffer.concat([label, Buffer.alloc(raw.length - label.length, '*')]) : Buffer.alloc(raw.length, '*')
        for (let at = buf.indexOf(raw, 0); at !== -1 && at < got; at = buf.indexOf(raw, at + raw.length)) {
          writeSync(fd, mask, 0, mask.length, start + at)
          mask.copy(buf, at)
          masked++
        }
      }
    return masked
  } finally {
    closeSync(fd)
  }
}
