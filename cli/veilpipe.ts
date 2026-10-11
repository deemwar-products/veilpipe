// veilpipe CLI: scan / test / add / rm / list / install. Node >= 22.18 runs this file as is.
import { spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

import { compile, deepMap, merge, onMatchArgv, parseLossless, redact, referencedNames, runTests, scan, scrubJsonl } from '../hooks/core.ts'
import type { Pattern, PatternsFile } from '../hooks/core.ts'
import { STATE_FILES, V2_FILE_DIRS, backupStore, compactStore, dataDir, findInStore, fixStore, planStore, recentFiles, stateDir, storePath } from '../opencode/store.ts'
import type { Db } from '../opencode/store.ts'
import { GLOBAL, Store, backend, checkName, scopeOf } from './secrets.ts'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULTS = join(ROOT, 'patterns.json')
// Vendored gitleaks rules (MIT), after ours so our names win a tie.
const VENDORED = join(ROOT, 'rules', 'gitleaks.json')

export function home(env = process.env): string {
  return env.VEILPIPE_HOME || join(env.HOME ?? homedir(), '.config', 'veilpipe')
}
const userFile = (env = process.env) => join(home(env), 'patterns.json')
const projectFile = (cwd: string) => join(cwd, '.veilpipe', 'patterns.json')

function readJson(path: string): PatternsFile | undefined {
  if (!existsSync(path)) return undefined
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    throw new Error(`${path}: ${(err as Error).message}`)
  }
}

// The same layers the mod reads: shipped defaults, vendored gitleaks rules, the user's file, the project's.
export function load(opts: { patterns?: string; cwd?: string; env?: NodeJS.ProcessEnv } = {}): PatternsFile {
  if (opts.patterns) return merge(readJson(opts.patterns))
  const cwd = opts.cwd ?? process.cwd()
  return merge(readJson(DEFAULTS), readJson(VENDORED), readJson(userFile(opts.env)), readJson(projectFile(cwd)))
}

// Shows a value without showing any of it: its length only. A prefix such as "sk_l" would reveal the key type and
// part of a real key, and on screen it reads like a redacted live key.
export function mask(v: string): string {
  return `${v.length} chars`
}

type Flags = { [k: string]: string | true | undefined }

function parse(argv: string[], switches: string[] = []): { pos: string[]; flags: Flags; multi: { [k: string]: string[] } } {
  const pos: string[] = []
  const flags: Flags = {}
  const multi: { [k: string]: string[] } = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (a === '--') {
      pos.push(...argv.slice(i + 1))
      break
    }
    // Only --name / --name=value is a flag: text that merely starts with dashes (a pasted PEM block,
    // '-----BEGIN ... KEY-----') is input to scan, never swallowed as a flag.
    if (/^--[a-z][\w-]*(=|$)/i.test(a)) {
      const [k, inline] = a.slice(2).split(/=(.*)/s, 2) as [string, string | undefined]
      const takesValue = ['patterns', 'group', 'name-group', 'flags', 'replace', 'hit', 'miss', 'dir', 'recent', 'days'].includes(k) && !switches.includes(k)
      const v = inline ?? (takesValue ? argv[++i] : true)
      if (v === undefined) throw new Error(`--${k} needs a value`)
      flags[k] = v
      if (typeof v === 'string') (multi[k] ??= []).push(v)
    } else pos.push(a)
  }
  return { pos, flags, multi }
}

function readInput(pos: string[]): string {
  if (pos.length === 0 || (pos.length === 1 && pos[0] === '-')) return readFileSync(0, 'utf8')
  if (pos.length === 1 && existsSync(pos[0]!) && lstatSync(pos[0]!).isFile()) return readFileSync(pos[0]!, 'utf8')
  return pos.join(' ')
}

// input: where a secret value is read from (stdin by default; tests pass their own).
type Out = { out: (s: string) => void; err: (s: string) => void; input?: () => string }

function scanCmd(pos: string[], flags: Flags, io: Out): number {
  const file = load({ patterns: flags.patterns as string | undefined })
  const r = redact(readInput(pos), compile(file))
  if (flags.json) {
    io.out(JSON.stringify({ text: r.text, found: r.fresh.map(f => ({ name: f.name, masked: mask(f.value) })) }, null, 2))
  } else {
    io.out(r.text)
    if (r.fresh.length === 0) io.err('veilpipe: nothing to replace')
    for (const f of r.fresh) io.err(`veilpipe: $${f.name}  ←  ${mask(f.value)}`)
  }
  if (flags.run) {
    if (!file.onMatch) io.err('veilpipe: --run given but no "onMatch" in the patterns file')
    else
      for (const f of r.fresh) {
        const [cmd, ...args] = onMatchArgv(file.onMatch, f.name)
        const p = spawnSync(cmd!, args, { input: f.value, stdio: ['pipe', 'inherit', 'inherit'] })
        if (p.status !== 0) io.err(`veilpipe: onMatch failed for $${f.name} (exit ${p.status ?? p.error?.message})`)
      }
  }
  return flags.check && r.fresh.length > 0 ? 1 : 0
}

function testCmd(flags: Flags, io: Out): number {
  const results = runTests(load({ patterns: flags.patterns as string | undefined }))
  for (const t of results) if (!t.ok || flags.verbose) io.out(`${t.ok ? 'ok  ' : 'FAIL'} ${t.label}${t.detail ? ` (${t.detail})` : ''}`)
  const failed = results.filter(t => !t.ok).length
  io.out(`${results.length - failed}/${results.length} passed`)
  return failed === 0 ? 0 : 1
}

function editUser(flags: Flags, fn: (f: PatternsFile) => void): string {
  const path = (flags.patterns as string | undefined) ?? userFile()
  const f: PatternsFile = readJson(path) ?? { patterns: [] }
  fn(f)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(f, null, 2) + '\n')
  return path
}

function addCmd(pos: string[], flags: Flags, multi: { [k: string]: string[] }, io: Out): number {
  const [name, regex] = pos
  if (!name || !regex) throw new Error('usage: veilpipe add <NAME> <regex> [--group N] [--flags i] [--replace T] [--hit EX]... [--miss EX]...')
  const p: Pattern = { name: name.replace(/^\$/, ''), regex }
  if (flags.group) p.group = Number(flags.group)
  if (flags['name-group']) p.nameGroup = Number(flags['name-group'])
  if (typeof flags.flags === 'string') p.flags = flags.flags
  if (typeof flags.replace === 'string') p.replace = flags.replace
  if (multi.hit || multi.miss) p.examples = { ...(multi.hit ? { hit: multi.hit } : {}), ...(multi.miss ? { miss: multi.miss } : {}) }
  // Refuse a pattern that does not compile or fails its own examples before writing it.
  const own = runTests({ patterns: [p] })
  const bad = own.filter(t => !t.ok)
  if (bad.length) {
    // The labels state what should happen ("X hits s", "X misses s"); say plainly that each one did not.
    io.err(`veilpipe: ${p.name} not added; it fails its own examples:`)
    for (const t of bad) io.err(`  FAIL ${t.label.replace(/^\S+ hits /, 'should match ').replace(/^\S+ misses /, 'should not match ')}${t.detail ? ` (${t.detail})` : ''}`)
    return 1
  }
  const path = editUser(flags, f => {
    f.patterns = [...f.patterns.filter(x => x.name !== p.name), p]
  })
  io.out(`veilpipe: added $${p.name} to ${path}${own.length ? ` (${own.length} examples pass)` : ''}`)
  return 0
}

function rmCmd(pos: string[], flags: Flags, io: Out): number {
  const name = pos[0]?.replace(/^\$/, '')
  if (!name) throw new Error('usage: veilpipe rm <NAME>')
  const shipped = (readJson(DEFAULTS)?.patterns ?? []).some(p => p.name === name)
  const path = editUser(flags, f => {
    f.patterns = f.patterns.filter(x => x.name !== name)
    // A shipped pattern cannot be deleted from the user's file, only switched off there.
    if (shipped) f.patterns.push({ name, regex: '.', disabled: true })
  })
  io.out(`veilpipe: ${shipped ? 'disabled' : 'removed'} $${name} in ${path}`)
  return 0
}

function listCmd(flags: Flags, io: Out): number {
  const f = load({ patterns: flags.patterns as string | undefined })
  for (const p of f.patterns) io.out(`${p.disabled ? '-' : '+'} $${p.name.padEnd(22)} ${p.regex}`)
  if (f.onMatch) io.out(`onMatch: ${JSON.stringify(f.onMatch)}`)
  return 0
}

function lexists(p: string): boolean {
  try {
    lstatSync(p)
    return true
  } catch {
    return false
  }
}

// A plugin folder under <config>/skills/<name> loads in every session (Claude Code 2.1.287+).
export function installTarget(flags: Flags, env = process.env, cwd = process.cwd()): string {
  if (typeof flags.dir === 'string') return resolve(flags.dir)
  if (flags.project) return join(cwd, '.claude', 'skills', 'veilpipe')
  return join(env.CLAUDE_CONFIG_DIR ?? join(env.HOME ?? homedir(), '.claude'), 'skills', 'veilpipe')
}

// opencode loads every file in <config>/opencode/plugins/; ours is a marked one-line shim that re-exports the plugin's
// default export, which serves 1.x (server) and 2.x (setup). Before 2.x support it re-exported VeilpipePlugin (1.x only).
const OC_MARK = '// veilpipe: installed by `veilpipe install --opencode`'
// Named to sort FIRST: opencode 2.x runs plugin hooks in file-name order, so a plugin sorting before ours saw the raw
// prompt and tool output (10-08, 2.0.23: a 'ctxguard.js' spy saw raw values with 'veilpipe.ts', none with this name).
// Before 10-08 the shim was 'veilpipe.ts'; install replaces it, uninstall removes either.
export const OC_SHIM_NAME = '00-veilpipe.ts'
const OC_OLD_NAME = 'veilpipe.ts'
export function opencodeTarget(env = process.env): string {
  return join(env.XDG_CONFIG_HOME ?? join(env.HOME ?? homedir(), '.config'), 'opencode', 'plugins', OC_SHIM_NAME)
}
const isOurs = (path: string) => existsSync(path) && readFileSync(path, 'utf8').startsWith(OC_MARK)
export const opencodeShim = () => `${OC_MARK}\nexport { default } from '${join(ROOT, 'opencode', 'veilpipe.ts')}'\n`

function installOpencode(io: Out, uninstall: boolean): number {
  const target = opencodeTarget()
  const old = join(dirname(target), OC_OLD_NAME)
  const ours = isOurs(target)
  if (uninstall) {
    if (!existsSync(target) && !isOurs(old)) return io.out(`veilpipe: not installed for opencode (${target})`), 0
    if (existsSync(target) && !ours) throw new Error(`${target} was not written by veilpipe; remove it yourself`)
    for (const p of [target, old]) if (isOurs(p)) rmSync(p), io.out(`veilpipe: removed ${p}`)
    return 0
  }
  if (existsSync(target) && !ours) throw new Error(`${target} already exists and is not veilpipe's; remove it first`)
  mkdirSync(dirname(target), { recursive: true })
  writeFileSync(target, opencodeShim())
  // Never two copies loaded: our old-named shim goes (a foreign file of that name is left alone).
  if (isOurs(old)) rmSync(old), io.out(`veilpipe: removed the old shim ${old} (renamed so it loads first)`)
  io.out(`veilpipe: wrote ${target} (loads ${join(ROOT, 'opencode', 'veilpipe.ts')})`)
  io.out('veilpipe: new opencode sessions load it; same patterns as Claude Code (shipped, ~/.config/veilpipe, ./.veilpipe)')
  return 0
}

function installCmd(flags: Flags, io: Out, uninstall = false): number {
  if (flags.opencode) return installOpencode(io, uninstall)
  // 10-11: a link in <project>/.claude/skills did not load the mod in claude -p sessions (the model saw a raw fake key),
  // so it is not offered; uninstall --project still removes an old link.
  if (flags.project && !uninstall)
    throw new Error('install --project does not protect every session (claude -p ignored it in testing); use veilpipe install (all sessions) or claude --plugin-dir ' + ROOT + ' (one session)')
  const target = installTarget(flags)
  const present = lexists(target)
  if (uninstall) {
    if (!present) return io.out(`veilpipe: not installed at ${target}`), 0
    if (!lstatSync(target).isSymbolicLink()) throw new Error(`${target} is not a veilpipe link; remove it yourself`)
    rmSync(target)
    io.out(`veilpipe: removed ${target}`)
    return 0
  }
  if (present) {
    if (lstatSync(target).isSymbolicLink() && resolve(dirname(target), readlinkSync(target)) === ROOT) {
      io.out(`veilpipe: already installed at ${target}`)
      return 0
    }
    throw new Error(`${target} already exists and is not this veilpipe; remove it first`)
  }
  mkdirSync(dirname(target), { recursive: true })
  symlinkSync(ROOT, target)
  io.out(`veilpipe: linked ${target} -> ${ROOT}`)
  io.out('veilpipe: new Claude Code sessions load it. One session only instead: claude --plugin-dir ' + ROOT)
  return 0
}

// --- audit ----------------------------------------------------------------------------------------------------
// Secrets that reached disk before veilpipe was installed: transcripts and prompt history.
// Reports counts and rule names only, never a value. --fix rewrites line by line through JSON,
// so a file can never be left invalid; unchanged lines stay byte-identical.

export type AuditFile = { path: string; hits: Record<string, number>; fixed?: boolean; skipped?: string }

// One distinct secret, identified only by a fingerprint: the first 12 hex of sha256(value).
export type Fingerprint = { fp: string; rules: string[]; hits: number; files: string[]; sec?: string }

export const fingerprint = (value: string) => createHash('sha256').update(value).digest('hex').slice(0, 12)

const ESC: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' }
export function unescapeJson(line: string): string {
  return line.replace(/\\(["\\/bfnrt])/g, (_, c: string) => ESC[c] ?? c)
}

// Every .jsonl under dir, each real file once. Symlinks are followed, but a dangling link is
// skipped (it used to abort the whole audit), a linked file is not counted twice next to its
// target, and a directory link back to an ancestor cannot loop.
function listJsonl(dir: string, seenFiles = new Set<string>()): string[] {
  const out: string[] = []
  const seenDirs = new Set<string>()
  const walk = (d: string) => {
    let names: string[] = []
    try {
      const real = realpathSync(d)
      if (seenDirs.has(real)) return
      seenDirs.add(real)
      names = readdirSync(d)
    } catch {
      return
    }
    for (const n of names) {
      const p = join(d, n)
      let st
      try {
        st = statSync(p)
      } catch {
        continue // dangling symlink
      }
      if (st.isDirectory()) walk(p)
      else if (n.endsWith('.jsonl')) {
        const real = realpathSync(p)
        if (!seenFiles.has(real)) (seenFiles.add(real), out.push(p))
      }
    }
  }
  walk(dir)
  return out.sort()
}

export function audit(opts: { config: string; fix?: boolean; includeEmail?: boolean; recentMinutes?: number; days?: number; patterns?: string; now?: number; collect?: Map<string, Fingerprint> }): AuditFile[] {
  const file = load({ patterns: opts.patterns })
  if (!opts.includeEmail) file.patterns = file.patterns.map(p => (p.name === 'EMAIL' ? { ...p, disabled: true } : p))
  const compiled = compile(file)
  const seen = new Set<string>()
  const files = listJsonl(join(opts.config, 'projects'), seen)
  const history = join(opts.config, 'history.jsonl')
  if (existsSync(history) && !seen.has(realpathSync(history))) files.push(history)
  const recent = (opts.recentMinutes ?? 10) * 60_000
  const now = opts.now ?? Date.now()
  const report: AuditFile[] = []
  for (const path of files) {
    // --days N: only files written in the last N days (10-10: '--recent 10080' was read as a 7-day filter; it is not).
    if (opts.days !== undefined && now - statSync(path).mtimeMs > opts.days * 86_400_000) continue
    const text = readFileSync(path, 'utf8')
    const known = new Map<string, string>()
    const hits: Record<string, number> = {}
    let changed = false
    const lines = text.split('\n').map(line => {
      // Fast path: one scan of the raw line; only lines with a hit are parsed and rewritten.
      // JSON escapes are undone first so "password": "x" inside a string (\"password\": \"x\") still matches.
      if (!line.trim() || scan(unescapeJson(line), compiled).length === 0) return line
      let row: unknown
      try {
        row = parseLossless(line)
      } catch {
        return line
      }
      let lineChanged = false
      const out = deepMap(row, s => {
        const r = redact(s, compiled, known)
        for (const h of r.hits) {
          hits[h.name] = (hits[h.name] ?? 0) + 1
          if (opts.collect) {
            const fp = fingerprint(h.value)
            const e = opts.collect.get(fp) ?? { fp, rules: [], hits: 0, files: [] }
            if (!e.rules.includes(h.name.replace(/_\d+$/, ''))) e.rules.push(h.name.replace(/_\d+$/, ''))
            if (!e.files.includes(path)) e.files.push(path)
            e.hits += 1
            opts.collect.set(fp, e)
          }
        }
        if (r.text !== s) lineChanged = true
        return r.text
      })
      if (!lineChanged) return line
      changed = true
      return JSON.stringify(out)
    })
    if (Object.keys(hits).length === 0) continue
    const entry: AuditFile = { path, hits }
    if (opts.fix && changed) {
      // Write to the link's target: renaming over a symlink would replace the link with a file.
      const target = realpathSync(path)
      if (now - statSync(target).mtimeMs < recent) entry.skipped = `written in the last ${opts.recentMinutes ?? 10} min (a live session?)`
      else if (readFileSync(target, 'utf8') !== text) entry.skipped = 'changed while scanning'
      else {
        const tmp = `${target}.veilpipe-tmp`
        writeFileSync(tmp, lines.join('\n'), { mode: statSync(target).mode })
        renameSync(tmp, target)
        entry.fixed = true
      }
    }
    report.push(entry)
  }
  return report
}

// Fingerprints of the sec vault's entries. Each value is hashed inside `sec run`'s child process,
// so only the hash prefix ever comes out. Returns fingerprint -> sec entry name(s); one value stored
// under two names keeps both (joined with ", ").
export function vaultFingerprints(run: Run = realRun): Map<string, string> {
  const out = new Map<string, string>()
  const ls = run(['sec', 'ls', '--json'])
  if (ls.status !== 0) return out
  for (const { name } of JSON.parse(ls.stdout) as { name: string }[]) {
    const r = run(['sec', 'run', `${name}=VEILPIPE_FP`, '--', 'sh', '-c', 'printf %s "$VEILPIPE_FP" | sha256sum'])
    const hex = r.stdout.match(/\b[0-9a-f]{64}\b/)?.[0]
    if (r.status === 0 && hex) {
      const fp = hex.slice(0, 12)
      out.set(fp, out.has(fp) ? `${out.get(fp)}, ${name}` : name)
    }
  }
  return out
}

// opencode's SQLite store (node:sqlite, Node 22.5+). Counts and rule names only, never a value.
// The TUI's state files (prompt history, stash): JSON lines, scanned string by string, fixed through scrubJsonl.
function auditOpencodeState(compiled: ReturnType<typeof compile>, fix: boolean, io: Out): number {
  let total = 0
  for (const f of STATE_FILES) {
    const path = join(stateDir(), f)
    if (!existsSync(path)) continue
    const text = readFileSync(path, 'utf8')
    const found = new Map<string, string>()
    for (const line of text.split('\n')) {
      let strings: string[] = []
      try {
        deepMap(JSON.parse(line), s => (strings.push(s), s))
      } catch {
        strings = [line]
      }
      for (const h of strings.flatMap(s => scan(s, compiled))) if (h.name !== 'EMAIL') found.set(h.value, h.name)
    }
    if (found.size === 0) continue
    total += found.size
    if (fix) writeFileSync(path, scrubJsonl(text, found))
    io.out(`${fix ? 'fixed' : 'found'} ${path}: ${found.size} distinct values`)
  }
  return total
}

// opencode's plain-text files outside the db: shell/ (2.x: every shell command's raw output) and log/ (2.x logs `run`'s
// argv). Fixed through the same redact() fixpoint as the db; each file is re-scanned before it is written, and a file
// still holding a match, or one that changed while scanning, is left as it was (counted, never forced).
const MAX_AUDIT_FILE = 64 * 1024 * 1024
function auditOpencodeFiles(compiled: ReturnType<typeof compile>, fix: boolean, io: Out): number {
  let total = 0
  for (const d of V2_FILE_DIRS) {
    const dir = join(dataDir(), d)
    const found = new Set<string>()
    let files = 0, fixed = 0, kept = 0, large = 0
    for (const path of recentFiles(dir, 0)) {
      if (statSync(path).size > MAX_AUDIT_FILE) {
        large++
        continue
      }
      const text = readFileSync(path, 'utf8')
      const hits = scan(text, compiled).filter(h => h.name !== 'EMAIL')
      if (hits.length === 0) continue
      files++
      for (const h of hits) found.add(h.value)
      if (!fix) {
        io.out(`  would rewrite ${path}`)
        continue
      }
      const next = redact(text, compiled, new Map()).text
      if (scan(next, compiled).some(h => h.name !== 'EMAIL') || readFileSync(path, 'utf8') !== text) {
        kept++
        continue
      }
      const tmp = `${path}.veilpipe-tmp`
      writeFileSync(tmp, next, { mode: statSync(path).mode })
      renameSync(tmp, path)
      fixed++
    }
    if (large) io.out(`skipped ${large} file(s) over ${MAX_AUDIT_FILE / 1024 / 1024} MiB in ${dir} (not scanned)`)
    if (files === 0) continue
    total += found.size
    io.out(`${fix ? `fixed ${fixed} of` : 'found'} ${files} file(s) in ${dir}: ${found.size} distinct values${kept ? `; ${kept} left unchanged (still matching or changed while scanning)` : ''}`)
  }
  return total
}

// Before --fix writes anything: a private copy (dir 0700, files 0600) of everything it may change: the whole store as
// one consistent snapshot (VACUUM INTO, WAL included), the TUI state files, and each shell/log file that holds a match.
// The copy holds the raw values by design (it is the way back), so it is named in the output with a delete reminder.
// Any failure here stops --fix before a single write.
function backupOpencode(compiled: ReturnType<typeof compile>, io: Out): string {
  const path = storePath()
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '-')
  const dir = join(dirname(path), `veilpipe-backup-${stamp}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const keep = (from: string, to: string) => {
    mkdirSync(dirname(to), { recursive: true, mode: 0o700 })
    copyFileSync(from, to)
    chmodSync(to, 0o600)
  }
  let n = 0
  if (existsSync(path)) {
    const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite')
    const db: Db = new DatabaseSync(path)
    try {
      backupStore(db, join(dir, 'opencode.db'))
    } finally {
      ;(db as any).close()
    }
    chmodSync(join(dir, 'opencode.db'), 0o600)
    n++
  }
  for (const f of STATE_FILES) if (existsSync(join(stateDir(), f))) keep(join(stateDir(), f), join(dir, 'state', f)), n++
  for (const d of V2_FILE_DIRS) {
    const base = join(dataDir(), d)
    for (const p of recentFiles(base, 0)) {
      if (statSync(p).size > MAX_AUDIT_FILE || !scan(readFileSync(p, 'utf8'), compiled).some(h => h.name !== 'EMAIL')) continue
      keep(p, join(dir, d, p.slice(base.length + 1)))
      n++
    }
  }
  io.out(`backup: ${n} file(s) in ${dir} (holds the raw values: delete it once opencode looks right: rm -r '${dir}')`)
  return dir
}

function auditOpencode(flags: Flags, io: Out): number {
  const path = storePath()
  const compiled = compile(load({ patterns: flags.patterns as string | undefined }))
  if (flags.fix && flags['dry-run']) return io.err('veilpipe: --dry-run and --fix together; pick one'), 2
  if (flags.fix) {
    try {
      backupOpencode(compiled, io)
    } catch (err) {
      return io.err(`veilpipe: backup failed, nothing was changed: ${(err as Error).message}`), 1
    }
  }
  const inState = auditOpencodeState(compiled, !!flags.fix, io) + auditOpencodeFiles(compiled, !!flags.fix, io)
  if (!existsSync(path)) return io.out(`veilpipe: no opencode store at ${path}`), inState && !flags.fix ? 1 : 0
  const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite')
  const db: Db = new DatabaseSync(path)
  try {
    const { found, cells } = findInStore(db, compiled)
    const byRule: Record<string, number> = {}
    for (const n of found.values()) byRule[n] = (byRule[n] ?? 0) + 1
    const what = Object.entries(byRule).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}×${n}`).join(' ')
    io.out(`opencode store ${path}: ${found.size} distinct values in ${cells} conversation cells${what ? `  ${what}` : ''}  (opencode's own login/credential tables are never read or changed)`)
    if (!flags.fix) {
      for (const p of planStore(db, compiled)) io.out(`  would rewrite ${p.table}.${p.column}: ${p.rows} row(s)`)
      return io.out(found.size + inState ? '  (dry run: nothing written. veilpipe audit --opencode --fix backs up, then replaces them with $NAME; close opencode first (2.x: opencode service stop); values are never printed)' : ''), found.size + inState ? 1 : 0
    }
    // One transaction, re-audited before commit; any error or a re-audit that does not drop to 0 rolls back.
    const r = fixStore(db, compiled)
    compactStore(db)
    io.out(`  fixed: ${r.changed} cell updates; re-audit ${r.before} -> ${r.after} distinct values; store compacted`)
    return 0
  } finally {
    ;(db as any).close()
  }
}

function auditCmd(flags: Flags, io: Out): number {
  if (flags.opencode) return auditOpencode(flags, io)
  if (flags.fingerprints) {
    const config = process.env.CLAUDE_CONFIG_DIR ?? join(process.env.HOME ?? homedir(), '.claude')
    const collect = new Map<string, Fingerprint>()
    audit({ config, includeEmail: !!flags['include-email'], patterns: flags.patterns as string | undefined, collect })
    const vault = flags.sec ? vaultFingerprints() : new Map<string, string>()
    const rows = [...collect.values()].map(f => ({ ...f, files: f.files.map(p => p.replace(config + '/', '')), ...(vault.has(f.fp) ? { sec: vault.get(f.fp) } : {}) }))
    rows.sort((a, b) => b.hits - a.hits)
    io.out(JSON.stringify({ distinct: rows.length, matchedToSec: rows.filter(r => r.sec).length, vaultEntries: vault.size, fingerprints: rows }, null, 2))
    return 0
  }
  const config = process.env.CLAUDE_CONFIG_DIR ?? join(process.env.HOME ?? homedir(), '.claude')
  // --recent is the live-file guard of --fix, not a time filter; say so, because it reads like one (10-10).
  if (flags.recent !== undefined) io.err(`veilpipe: --recent ${flags.recent} only makes --fix skip files written in the last ${flags.recent} min (a live session); it does not limit the audit. For files written in the last N days: --days N`)
  const days = flags.days !== undefined ? Number(flags.days) : undefined
  if (days !== undefined && !(days > 0)) return io.err('veilpipe: --days needs a number of days'), 2
  const report = audit({ config, fix: !!flags.fix, includeEmail: !!flags['include-email'], recentMinutes: flags.recent ? Number(flags.recent) : undefined, days, patterns: flags.patterns as string | undefined })
  if (flags.json) {
    io.out(JSON.stringify(report.map(r => ({ ...r, path: r.path.replace(config + '/', '') })), null, 2))
  } else {
    for (const r of report) {
      const what = Object.entries(r.hits).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}×${n}`).join(' ')
      io.out(`${r.fixed ? 'fixed ' : r.skipped ? 'skip  ' : 'found '} ${r.path.replace(config + '/', '')}  ${what}${r.skipped ? `  (${r.skipped})` : ''}`)
    }
    const total = report.reduce((a, r) => a + Object.values(r.hits).reduce((x, y) => x + y, 0), 0)
    io.out(`${report.length} file${report.length === 1 ? '' : 's'} with secrets, ${total} values${flags.fix ? `, ${report.filter(r => r.fixed).length} rewritten` : '  (veilpipe audit --fix rewrites them; values are never printed)'}`)
  }
  return report.length > 0 && !flags.fix ? 1 : 0
}

// --- doctor -------------------------------------------------------------------------------------------------

type Run = (argv: string[], o?: { cwd?: string; env?: NodeJS.ProcessEnv }) => { status: number | null; stdout: string }
const realRun: Run = ([cmd, ...args], o = {}) => {
  const p = spawnSync(cmd!, args, { encoding: 'utf8', timeout: 180_000, ...(o.cwd ? { cwd: o.cwd } : {}), ...(o.env ? { env: o.env } : {}) })
  return { status: p.error ? null : p.status, stdout: p.stdout ?? '' }
}

type Check = { level: 'ok' | 'warn' | 'fail'; name: string; detail: string }

// Obviously fake, matched by the shipped STRIPE_KEY pattern.
const CANARY = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKE00'
const MIN_CLAUDE = [2, 1, 287]

function atLeast(v: string, min: number[]): boolean {
  const parts = v.split('.').map(Number)
  for (let i = 0; i < min.length; i++) if ((parts[i] ?? 0) !== min[i]) return (parts[i] ?? 0) > min[i]!
  return true
}

export function doctor(opts: { canary?: boolean; run?: Run; env?: NodeJS.ProcessEnv; cwd?: string } = {}): Check[] {
  const run = opts.run ?? realRun
  const env = opts.env ?? process.env
  const config = env.CLAUDE_CONFIG_DIR ?? join(env.HOME ?? homedir(), '.claude')
  const checks: Check[] = []
  const add = (level: Check['level'], name: string, detail: string) => checks.push({ level, name, detail })

  const node = process.versions.node
  add(atLeast(node, [22, 18]) ? 'ok' : 'fail', 'node', `${node} (needs 22.18+ to run the CLI's TypeScript)`)

  const v = run(['claude', '--version'])
  const cv = v.stdout.match(/\d+\.\d+\.\d+/)?.[0]
  if (v.status !== 0 || !cv) add('fail', 'claude', 'Claude Code not found on PATH')
  else add(atLeast(cv, MIN_CLAUDE) ? 'ok' : 'fail', 'claude', `${cv} (mods need ${MIN_CLAUDE.join('.')}+)`)

  try {
    const file = load({ cwd: opts.cwd, env })
    const n = compile(file).length
    const vendored = file.patterns.filter(p => p.source?.startsWith('gitleaks:') && !p.disabled).length
    add('ok', 'patterns', `${n} active (${vendored} from gitleaks)`)
    const failed = runTests(file).filter(t => !t.ok)
    add(failed.length ? 'fail' : 'ok', 'suite', failed.length ? `${failed.length} failing: ${failed[0]!.label}` : 'every example and rewrite test passes')
  } catch (err) {
    add('fail', 'patterns', `${(err as Error).message}: the mod refuses every prompt until this loads`)
  }

  const link = join(config, 'skills', 'veilpipe')
  const linked = lexists(link) && lstatSync(link).isSymbolicLink() && resolve(dirname(link), readlinkSync(link)) === ROOT
  const listed = !linked && /veilpipe@\S+[\s\S]{0,120}enabled/.test(run(['claude', 'plugin', 'list']).stdout)
  add(linked || listed ? 'ok' : 'warn', 'installed', linked ? link : listed ? 'veilpipe@<marketplace>, enabled' : 'not installed: veilpipe install (or claude --plugin-dir ' + ROOT + ')')

  try {
    const settings = JSON.parse(readFileSync(join(config, 'settings.json'), 'utf8'))
    add(settings.disableAllHooks ? 'fail' : 'ok', 'settings', settings.disableAllHooks ? 'disableAllHooks is true: no mod runs' : 'hooks enabled')
  } catch {
    add('ok', 'settings', 'no settings.json (hooks enabled by default)')
  }

  // opencode is optional: checked only when it is on PATH.
  const oc = run(['opencode', '--version'])
  const ocv = oc.stdout.match(/\d+\.\d+\.\d+/)?.[0]
  if (oc.status === 0 && ocv) {
    const shim = opencodeTarget(env)
    const old = join(dirname(shim), OC_OLD_NAME)
    const v2 = Number(ocv.split('.')[0]) >= 2
    const cur = existsSync(shim) ? readFileSync(shim, 'utf8') : undefined
    const oldText = isOurs(old) ? readFileSync(old, 'utf8') : undefined
    const installed = cur === opencodeShim() ? shim : oldText !== undefined ? old : undefined
    // opencode 2.x has a new plugin API (default export { id, setup }); a shim from before 2.x support loads nothing
    // there (10-08: canary on 2.0.22, raw key sent to the model ×2), so it must not look installed.
    if (cur === opencodeShim()) add('ok', 'opencode', `${ocv}; plugin ${shim}`)
    else if (cur?.startsWith(OC_MARK)) add(v2 ? 'fail' : 'warn', 'opencode', `${ocv}: ${shim} is stale: veilpipe install --opencode`)
    else if (existsSync(shim)) add('warn', 'opencode', `${ocv}: ${shim} is not ours: remove it, then veilpipe install --opencode`)
    else if (oldText !== undefined && v2 && oldText !== opencodeShim()) add('fail', 'opencode', `${ocv}: NOT protected: ${old} predates opencode 2.x support; run veilpipe install --opencode`)
    else if (oldText !== undefined) add('warn', 'opencode', `${ocv}; plugin ${old} has the old name, so other plugins can run before it: veilpipe install --opencode`)
    else add('warn', 'opencode', `${ocv}; not protected: veilpipe install --opencode`)
    // A plugin whose hooks run before veilpipe's sees the message and tool output raw. 2.x runs them in file-name order
    // (10-08, 2.0.23: only plugins sorting before ours saw raw values); 1.x in directory-listing order (10-06: a spy saw
    // raw values in 3 of 4 namings), so on 1.x every other plugin is named.
    const first = installed ? installed.slice(dirname(installed).length + 1) : OC_SHIM_NAME
    const others = [dirname(shim), join(opts.cwd ?? process.cwd(), '.opencode', 'plugins')].flatMap(d => {
      try {
        return readdirSync(d).filter(f => /\.(ts|js|mjs)$/.test(f) && join(d, f) !== shim && !isOurs(join(d, f)) && (!v2 || f < first)).map(f => join(d, f))
      } catch {
        return []
      }
    })
    // OPENCODE_PURE=1 makes opencode load no external plugin at all (10-06: canary raw 4 sent, 81 stored).
    if (env.OPENCODE_PURE) add('fail', 'opencode pure', 'OPENCODE_PURE is set: opencode loads no plugins, so sessions started from this shell are NOT protected')
    if (others.length) add('warn', 'opencode plugins', `${others.length} other plugin(s) may see raw text before veilpipe: ${others.join(', ')}`)
    if (opts.canary) {
      const c = run([join(ROOT, 'opencode', 'canary.sh')])
      add(c.status === 0 ? 'ok' : 'fail', 'canary: opencode', c.status === 0 ? 'opencode run with a fake key: model and store hold 0 raw copies (mock model, $0)' : `FAILED: ${c.stdout.trim().split('\n').map(l => l.trim()).join(' | ')}`)
    }
  }

  // `audit --opencode --fix` backups hold the raw values by design (the way back). Checked whether or not opencode is
  // still on PATH: a backup outlives an uninstall, and a forgotten one keeps every secret it cleaned on disk.
  const bakDir = dirname(storePath(env))
  const baks = existsSync(bakDir) ? readdirSync(bakDir).filter(f => f.startsWith('veilpipe-backup-')).map(f => join(bakDir, f)) : []
  if (baks.length)
    add('warn', 'opencode backups', `${baks.length} backup(s) from audit --opencode --fix still hold the raw values; once opencode looks right: ${baks.map(b => `rm -r '${b}'`).join('; ')}`)

  if (opts.canary) {
    const sid = randomUUID()
    // VEILPIPE_NO_STORE: the fake key must not be auto-saved into the person's store.
    const r = run(['claude', '-p', '--model', 'sonnet', '--plugin-dir', ROOT, '--session-id', sid, `Repeat my message back verbatim in backticks, then stop: deploy with ${CANARY}`], { env: { ...env, VEILPIPE_NO_STORE: '1' } })
    const sawName = r.stdout.includes('$STRIPE_KEY')
    const sawRaw = r.stdout.includes(CANARY)
    add(sawName && !sawRaw ? 'ok' : 'fail', 'canary: model', sawRaw ? 'the model saw the raw fake key' : sawName ? 'the model saw $STRIPE_KEY' : `no answer to judge (exit ${r.status})`)
    const transcript = findTranscript(join(config, 'projects'), sid)
    if (!transcript) add('warn', 'canary: disk', 'no transcript found for the canary session')
    else {
      const raw = readFileSync(transcript, 'utf8').split(CANARY).length - 1
      add(raw === 0 ? 'ok' : 'fail', 'canary: disk', raw === 0 ? 'transcript holds 0 copies of the fake key' : `transcript holds ${raw} raw copies`)
    }
  }
  storeChecks(add, { env, run, config, canary: !!opts.canary })
  return checks
}

// Obviously fake, and stored only for the length of the store canary.
const STORE_CANARY = 'sk_live_FAKESTORECANARYFAKESTORE00'

// The secret store: it opens with its key (Keychain on macOS), its files are private, no project folder of it has
// gone missing. --canary: a fake value is stored for a scratch project, a real session fills it into a command, and
// the model and transcript never hold it; the entry and the scratch folder are removed after.
function storeChecks(add: (l: Check['level'], n: string, d: string) => void, o: { env: NodeJS.ProcessEnv; run: Run; config: string; canary: boolean }) {
  const store = new Store(home(o.env), o.env)
  let where = 'a key file'
  try {
    where = backend(o.env) === 'keychain' ? 'the macOS Keychain' : join(store.dir, 'key')
    if (!store.exists()) add('ok', 'store', `empty; caught values are saved on first use (key in ${where})`)
    else {
      const entries = store.read()
      const loose = [store.file, join(store.dir, 'key')].filter(f => existsSync(f) && (statSync(f).mode & 0o077) !== 0)
      const scopes = new Set(entries.map(e => e.scope)).size
      add(loose.length ? 'fail' : 'ok', 'store', loose.length ? `readable by others: chmod 600 ${loose.join(' ')}` : `${entries.length} secret(s) in ${scopes} scope(s); key in ${where}`)
      for (const g of store.orphans())
        add('warn', 'store: moved?', `${g.count} secret(s) belong to ${g.scope}, which no longer exists; if the project moved: veilpipe secret move '${g.scope}' NEW_FOLDER`)
    }
  } catch (err) {
    add('fail', 'store', (err as Error).message)
    return
  }
  if (!o.canary) return
  const dir = join(o.env.TMPDIR ?? '/tmp', `veilpipe-store-canary-${randomUUID()}`)
  mkdirSync(join(dir, '.git'), { recursive: true })
  const scope = scopeOf(dir)
  try {
    store.add(scope, 'VEILPIPE_CANARY', STORE_CANARY)
    const sid = randomUUID()
    const r = o.run(['claude', '-p', '--model', 'sonnet', '--plugin-dir', ROOT, '--allowedTools=Bash', '--session-id', sid,
      'Run exactly this one Bash command and reply with its output only: printf %s "$VEILPIPE_CANARY" | wc -c'], { cwd: dir })
    const got = r.stdout.match(/\d+/)?.[0]
    const raw = r.stdout.includes(STORE_CANARY)
    const transcript = findTranscript(join(o.config, 'projects'), sid)
    const onDisk = transcript ? readFileSync(transcript, 'utf8').split(STORE_CANARY).length - 1 : 0
    const ok = got === String(STORE_CANARY.length) && !raw && onDisk === 0
    add(ok ? 'ok' : 'fail', 'canary: store', ok ? `a stored fake value was filled into a real command in a new session (${got} chars); model and transcript hold 0 copies (key in ${where})`
      : raw || onDisk ? `the raw fake value reached the ${raw ? 'model' : 'transcript'}` : `the command did not get the stored value (got ${got ?? 'no answer'}, expected ${STORE_CANARY.length})`)
    if (transcript) rmSync(transcript, { force: true })
  } finally {
    try { store.rm(scope, 'VEILPIPE_CANARY') } catch {}
    rmSync(dir, { recursive: true, force: true })
  }
}

function findTranscript(projects: string, sid: string): string | undefined {
  try {
    for (const d of readdirSync(projects)) {
      const p = join(projects, d, `${sid}.jsonl`)
      if (existsSync(p)) return p
    }
  } catch {}
  return undefined
}

function doctorCmd(flags: Flags, io: Out): number {
  const checks = doctor({ canary: !!flags.canary })
  const mark = { ok: '✔', warn: '!', fail: '✖' } as const
  for (const c of checks) io.out(`${mark[c.level]} ${c.name.padEnd(13)} ${c.detail}`)
  if (!flags.canary) io.out('  (veilpipe doctor --canary also sends a fake key through claude -p, ~$0.02, and greps the transcript)')
  return checks.some(c => c.level === 'fail') ? 1 : 0
}

const HELP = `veilpipe: rewrite secrets to $NAME before Claude sees them.

  veilpipe scan [text | file | -]   show what the model would see (stderr lists each value, masked)
       --json  --check (exit 1 on a match)  --run (run "onMatch" for each value)
  veilpipe test [--verbose]         run every pattern's examples and the rewrite tests
  veilpipe add NAME REGEX [--group N] [--name-group N] [--flags i] [--replace T] [--hit EX] [--miss EX]
  veilpipe rm NAME                  remove (or switch off a shipped) pattern
  veilpipe list                     the merged patterns: shipped, ~/.config/veilpipe, ./.veilpipe
  veilpipe install [--dir PATH]     load the mod in every Claude Code session
  veilpipe uninstall [--dir PATH]   (--project removes a link made by an older version)
  veilpipe install --opencode / uninstall --opencode   the same protection for opencode (global plugin)
  veilpipe audit --fingerprints [--sec]   one row per distinct secret: sha256 prefix, rules, files; --sec names the vault entry it matches
  veilpipe audit [--fix] [--days N] [--include-email] [--recent MIN] [--json]
                                     find secrets already in transcripts + history (counts only; ALL files unless --days N);
                                     --fix rewrites them, skipping files written in the last --recent MIN (default 10)
  veilpipe audit --opencode [--dry-run|--fix]  the same for opencode's session store (opencode.db), TUI history, shell output and logs;
                                     without --fix it lists the table.columns, rows and files --fix would rewrite; --fix backs up first
  veilpipe doctor [--canary]        is it installed and working? --canary runs a fake key through claude -p
  veilpipe secret add NAME [--global] [--replace]   store a value (from stdin or a prompt, never argv) for this project
  veilpipe secret ls [--global | --all]   names, lengths and dates (--all: every scope, names only); never values
  veilpipe secret rm NAME [--global]
  veilpipe exec 'command using $NAME'   run it with the stored values filled in; its output shows $NAME, never the value
  veilpipe secret move OLD_FOLDER NEW_FOLDER   a project folder moved or was renamed: its secrets follow
                                     scope = the nearest git root (else the folder); --global is the fallback scope

  --patterns FILE   use only this patterns file (add/rm edit it)`

// Called by the mod for a transcript/history file over the engine's 4 MiB read limit.
// stdin: JSON [[value, name], ...]. Rewrites the file only if it did not change while being
// scrubbed (a live session appends to it); otherwise retries. Prints clean|scrubbed|busy.
// A symlink is followed (the target is rewritten, the link stays); the swap is tmp + rename in the same folder.
export function scrubLargeFile(path: string, known: Map<string, string>, attempts = 5, beforeSwap: () => void = () => {}): 'clean' | 'scrubbed' | 'busy' {
  const real = realpathSync(path)
  for (let i = 0; i < attempts; i++) {
    const before = statSync(real)
    const text = readFileSync(real, 'utf8')
    const clean = scrubJsonl(text, known)
    if (clean === text) return 'clean'
    const tmp = `${real}.veilpipe-${process.pid}`
    writeFileSync(tmp, clean, { mode: before.mode })
    beforeSwap()
    // Size/mtime can miss a same-size rewrite within the mtime tick: compare the bytes too.
    const now = statSync(real)
    if (now.size !== before.size || now.mtimeMs !== before.mtimeMs || readFileSync(real, 'utf8') !== text) {
      rmSync(tmp)
      continue
    }
    renameSync(tmp, real)
    return 'scrubbed'
  }
  return 'busy'
}

// A value typed at a terminal is read without echo; otherwise it is stdin. Never argv.
function readSecret(io: Out): string {
  if (io.input) return io.input()
  if (process.stdin.isTTY) {
    process.stderr.write('value (not shown): ')
    const r = spawnSync('sh', ['-c', 'stty -echo; IFS= read -r v; s=$?; stty echo; printf %s "$v"; exit $s'], { stdio: ['inherit', 'pipe', 'inherit'], encoding: 'utf8' })
    process.stderr.write('\n')
    return r.stdout
  }
  return readFileSync(0, 'utf8').replace(/\r?\n$/, '')
}

const shq = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`

// veilpipe exec 'command': runs it with sh -c, the stored values of the names it uses in its environment, and
// prints its output with every stored value of this project replaced by its $NAME. The exit code passes through.
function execCmd(pos: string[], io: Out): number {
  if (pos.length !== 1) throw new Error(`usage: veilpipe exec 'command using $NAME'  (one quoted argument, so your shell does not expand $NAME first)`)
  const command = pos[0]!
  const store = new Store(home())
  const vis = store.exists() ? store.visible(scopeOf(process.cwd())) : []
  const used = referencedNames(command).filter(n => vis.some(e => e.name === n))
  const env = { ...process.env, ...Object.fromEntries(used.map(n => [n, vis.find(e => e.name === n)!.value])) }
  const r = spawnSync('sh', ['-c', command], { env, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['inherit', 'pipe', 'pipe'] })
  const known = new Map(vis.map(e => [e.value, e.name] as [string, string]))
  const clean = (t: string) => [...known].sort((a, b) => b[0].length - a[0].length).reduce((acc, [v, n]) => acc.split(v).join(`$${n}`), t)
  if (r.stdout) process.stdout.write(clean(r.stdout))
  if (r.stderr) process.stderr.write(clean(r.stderr))
  if (r.error) throw r.error
  return r.status ?? 1
}

function secretCmd(pos: string[], flags: Flags, io: Out): number {
  const [sub, ...args] = pos
  const store = new Store(home())
  const scope = flags.global ? GLOBAL : scopeOf(process.cwd())
  const shown = (s: string) => (s === GLOBAL ? 'global' : s)
  switch (sub) {
    case 'add': {
      if (args.length !== 1) throw new Error('usage: veilpipe secret add NAME [--global] [--replace]  (the value comes from stdin or a prompt, never the command line)')
      const name = checkName(args[0]!.replace(/^\$/, ''))
      const how = store.add(scope, name, readSecret(io), flags.replace === true)
      io.out(`${how} $${name} for ${shown(scope)}`)
      return 0
    }
    case 'ls': {
      const entries = store.read()
      if (flags.all) {
        for (const e of entries) io.out(`${shown(e.scope)}\t$${e.name}`)
        return 0
      }
      for (const e of entries.filter(e => e.scope === scope)) io.out(`$${e.name}\t${mask(e.value)}\t${e.created.slice(0, 10)}`)
      if (!flags.global) for (const e of entries.filter(e => e.scope === GLOBAL && !entries.some(p => p.scope === scope && p.name === e.name)))
        io.out(`$${e.name}\t${mask(e.value)}\t${e.created.slice(0, 10)}\t(global)`)
      return 0
    }
    case 'rm': {
      if (args.length !== 1) throw new Error('usage: veilpipe secret rm NAME [--global]')
      const name = checkName(args[0]!.replace(/^\$/, ''))
      if (!store.rm(scope, name)) {
        io.err(`$${name} is not stored for ${shown(scope)}`)
        return 1
      }
      io.out(`removed $${name} from ${shown(scope)}`)
      return 0
    }
    case 'move': {
      if (args.length !== 2) throw new Error('usage: veilpipe secret move OLD_FOLDER NEW_FOLDER')
      const n = store.move(resolve(args[0]!), scopeOf(args[1]!))
      io.out(`moved ${n} secret(s) to ${scopeOf(args[1]!)}`)
      return 0
    }
    // For the mod only (it runs these itself; the hook denies them in commands the model writes).
    // _load DIR: {scope, entries: [[value, name], ...]} for what DIR's project resolves.
    case '_load': {
      const sc = scopeOf(args[0] ?? process.cwd())
      io.out(JSON.stringify({ scope: sc, entries: store.exists() ? store.visible(sc).map(e => [e.value, e.name]) : [] }))
      return 0
    }
    // _save SCOPE NAME, value on stdin: saved | first | exists | conflict.
    case '_save': {
      if (args.length !== 2) throw new Error('usage: _save SCOPE NAME (value on stdin)')
      io.out(store.put(args[0]!, args[1]!, readSecret(io)))
      return 0
    }
    // _fill SCOPE NAME...: shell code that exports each value, read by the prefix the hook adds; exit 1 if one is missing.
    case '_fill': {
      const [sc, ...names] = args
      const vis = store.visible(sc!)
      const missing = names.filter(n => !vis.some(e => e.name === n))
      if (missing.length) {
        io.err(`veilpipe: ${missing.map(n => `$${n}`).join(', ')} not in the store for ${shown(sc!)}`)
        return 1
      }
      for (const n of names) io.out(`export ${checkName(n)}=${shq(vis.find(e => e.name === n)!.value)}`)
      return 0
    }
    default:
      throw new Error('usage: veilpipe secret add|ls|rm|move (see veilpipe help)')
  }
}

function scrubFileCmd(pos: string[], io: Out): number {
  const path = pos[0]
  if (!path) { io.err('usage: veilpipe scrub-file PATH  (known values as JSON on stdin)'); return 2 }
  io.out(scrubLargeFile(path, new Map<string, string>(JSON.parse(readFileSync(0, 'utf8')))))
  return 0
}

export function main(argv: string[], io: Out = { out: s => console.log(s), err: s => console.error(s) }): number {
  const [cmd, ...rest] = argv
  try {
    // exec takes its command whole, never as flags.
    const { pos, flags, multi } = cmd === 'exec' ? { pos: rest, flags: {} as Flags, multi: {} } : parse(rest, cmd === 'secret' ? ['replace'] : [])
    switch (cmd) {
      case 'scan':
        return scanCmd(pos, flags, io)
      case 'test':
        return testCmd(flags, io)
      case 'add':
        return addCmd(pos, flags, multi, io)
      case 'rm':
        return rmCmd(pos, flags, io)
      case 'list':
        return listCmd(flags, io)
      case 'install':
        return installCmd(flags, io)
      case 'uninstall':
        return installCmd(flags, io, true)
      case 'audit':
        return auditCmd(flags, io)
      case 'scrub-file':
        return scrubFileCmd(pos, io)
      case 'doctor':
        return doctorCmd(flags, io)
      case 'secret':
        return secretCmd(pos, flags, io)
      case 'exec':
        return execCmd(pos, io)
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        io.out(HELP)
        return 0
      default:
        io.err(`veilpipe: unknown command ${cmd}\n\n${HELP}`)
        return 2
    }
  } catch (err) {
    io.err(`veilpipe: ${(err as Error).message}`)
    return 2
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2))
