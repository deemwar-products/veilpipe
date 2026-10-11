// Veilpipe's own secret store: values caught as $NAME, kept encrypted so a later command (or session) can use them
// without the model ever seeing them. One AES-256-GCM file, mode 0600. Its key is in the macOS Keychain, or in a
// 0600 key file elsewhere. Names are scoped to a project (the nearest git root, else the folder itself), with a global
// scope as the fallback. A value is never taken from argv, never printed, never written anywhere but the store.
import { spawnSync } from 'node:child_process'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { userInfo } from 'node:os'
import { dirname, join } from 'node:path'

export const GLOBAL = '(global)'
export type Entry = { scope: string; name: string; value: string; created: string }
type Plain = { v: 1; entries: Entry[] }

const KEYCHAIN_SERVICE = 'veilpipe-store'
const NAME = /^[A-Z_][A-Z0-9_]*$/

export function checkName(name: string): string {
  if (!NAME.test(name)) throw new Error(`'${name}' is not a name: use A-Z, 0-9 and _, not starting with a digit (e.g. STRIPE_KEY)`)
  return name
}

// The project a folder belongs to: the nearest folder above it (or itself) holding .git, else the folder itself.
export function scopeOf(cwd: string): string {
  const start = realpathSync(cwd)
  for (let d = start; ; d = dirname(d)) {
    if (existsSync(join(d, '.git'))) return d
    if (dirname(d) === d) return start
  }
}

export type Backend = 'keychain' | 'file'
export function backend(env = process.env): Backend {
  const b = env.VEILPIPE_STORE_BACKEND
  if (b === 'keychain' || b === 'file') return b
  return process.platform === 'darwin' ? 'keychain' : 'file'
}

function writePrivate(path: string, data: string) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, data, { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, path)
}

// The store key, created on first use. Keychain: `security -i` reads the add command from stdin, so the key is never
// in any process's argv.
function storeKey(dir: string, env = process.env, create = true): Buffer | undefined {
  const account = userInfo().username
  if (backend(env) === 'keychain') {
    const r = spawnSync('security', ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account, '-w'], { encoding: 'utf8' })
    if (r.status === 0 && /^[0-9a-f]{64}$/.test(r.stdout.trim())) return Buffer.from(r.stdout.trim(), 'hex')
    if (!create) return undefined
    const hex = randomBytes(32).toString('hex')
    const add = spawnSync('security', ['-i'], { input: `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${account} -w ${hex}\n`, encoding: 'utf8' })
    if (add.status !== 0) throw new Error('could not save the store key in the Keychain (security add-generic-password failed)')
    return Buffer.from(hex, 'hex')
  }
  const path = join(dir, 'key')
  if (existsSync(path)) {
    const hex = readFileSync(path, 'utf8').trim()
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`${path} is not a veilpipe store key`)
    return Buffer.from(hex, 'hex')
  }
  if (!create) return undefined
  const hex = randomBytes(32).toString('hex')
  writePrivate(path, `${hex}\n`)
  return Buffer.from(hex, 'hex')
}

function encrypt(key: Buffer, plain: Plain): string {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.concat([c.update(JSON.stringify(plain), 'utf8'), c.final()])
  return JSON.stringify({ v: 1, alg: 'aes-256-gcm', iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') }) + '\n'
}

function decrypt(key: Buffer, text: string, path: string): Plain {
  try {
    const f = JSON.parse(text)
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(f.iv, 'base64'))
    d.setAuthTag(Buffer.from(f.tag, 'base64'))
    return JSON.parse(Buffer.concat([d.update(Buffer.from(f.data, 'base64')), d.final()]).toString('utf8'))
  } catch {
    throw new Error(`${path} could not be decrypted with the store key (a different key, or the file was changed)`)
  }
}

export class Store {
  readonly dir: string
  readonly file: string
  private env: NodeJS.ProcessEnv
  constructor(home: string, env = process.env) {
    this.dir = join(home, 'store')
    this.file = join(this.dir, 'secrets.enc')
    this.env = env
  }

  exists(): boolean {
    return existsSync(this.file)
  }

  read(): Entry[] {
    if (!this.exists()) return []
    const key = storeKey(this.dir, this.env, false)
    if (!key) throw new Error(`${this.file} exists but its key is missing (${backend(this.env) === 'keychain' ? 'Keychain item veilpipe-store' : join(this.dir, 'key')})`)
    return decrypt(key, readFileSync(this.file, 'utf8'), this.file).entries
  }

  // Read, change and write under an exclusive lock file (O_EXCL), so two sessions never lose each other's writes.
  update<T>(fn: (entries: Entry[]) => T): T {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 })
    const lock = join(this.dir, 'lock')
    let fd: number | undefined
    for (let i = 0; i < 200 && fd === undefined; i++) {
      try {
        fd = openSync(lock, 'wx', 0o600)
      } catch {
        // A lock left by a crashed writer is stale after 10 s.
        try { if (Date.now() - statSync(lock).mtimeMs > 10_000) rmSync(lock) } catch {}
        spawnSync('sleep', ['0.05'])
      }
    }
    if (fd === undefined) throw new Error(`${lock} is held by another veilpipe; try again`)
    try {
      const entries = this.read()
      const out = fn(entries)
      writePrivate(this.file, encrypt(storeKey(this.dir, this.env)!, { v: 1, entries }))
      return out
    } finally {
      closeSync(fd)
      rmSync(lock, { force: true })
    }
  }

  // `secret add`: refuses a taken name unless replace.
  add(scope: string, name: string, value: string, replace = false): 'added' | 'replaced' {
    checkName(name)
    if (!value) throw new Error('empty value; nothing stored')
    return this.update(entries => {
      const i = entries.findIndex(e => e.scope === scope && e.name === name)
      if (i >= 0 && !replace) throw new Error(`$${name} is already stored for ${scope}; use --replace to change it`)
      const e = { scope, name, value, created: new Date().toISOString() }
      if (i >= 0) entries[i] = e
      else entries.push(e)
      return i >= 0 ? 'replaced' : 'added'
    })
  }

  // Auto-save: the same value in this scope keeps its name; a new value under a taken name gets NAME_2, NAME_3, ...
  // Never overwrites. Returns the name the value is stored under.
  save(scope: string, base: string, value: string): string {
    checkName(base)
    return this.update(entries => {
      const mine = entries.filter(e => e.scope === scope)
      const same = mine.find(e => e.value === value)
      if (same) return same.name
      const taken = new Set(mine.map(e => e.name))
      let name = base
      for (let i = 2; taken.has(name); i++) name = `${base}_${i}`
      entries.push({ scope, name, value, created: new Date().toISOString() })
      return name
    })
  }

  // The hook's save: the session already named the value, so store it under exactly that name. 'exists' when the
  // same value is there; 'conflict' when another value took the name meanwhile (another session): nothing changes.
  // 'first' marks the first secret saved for this scope (the hook tells the user once).
  put(scope: string, name: string, value: string): 'saved' | 'first' | 'exists' | 'conflict' {
    checkName(name)
    return this.update(entries => {
      const mine = entries.filter(e => e.scope === scope)
      const had = mine.find(e => e.name === name)
      if (had) return had.value === value ? 'exists' : 'conflict'
      entries.push({ scope, name, value, created: new Date().toISOString() })
      return mine.length === 0 ? 'first' : 'saved'
    })
  }

  // What a scope resolves: its own names, then global names it does not have. value -> name.
  visible(scope: string): Entry[] {
    const entries = this.read()
    const mine = entries.filter(e => e.scope === scope)
    return [...mine, ...entries.filter(e => e.scope === GLOBAL && !mine.some(m => m.name === e.name))]
  }

  // Project first, then global.
  lookup(scope: string, name: string): Entry | undefined {
    const entries = this.read()
    return entries.find(e => e.scope === scope && e.name === name) ?? entries.find(e => e.scope === GLOBAL && e.name === name)
  }

  rm(scope: string, name: string): boolean {
    return this.update(entries => {
      const i = entries.findIndex(e => e.scope === scope && e.name === name)
      if (i >= 0) entries.splice(i, 1)
      return i >= 0
    })
  }

  // Re-scope every entry of a moved or renamed project folder. Refuses when the new scope already has one of the names.
  move(from: string, to: string): number {
    return this.update(entries => {
      const moving = entries.filter(e => e.scope === from)
      const clash = moving.filter(m => entries.some(e => e.scope === to && e.name === m.name)).map(m => `$${m.name}`)
      if (clash.length) throw new Error(`${to} already has ${clash.join(', ')}; remove or rename those first`)
      for (const e of moving) e.scope = to
      return moving.length
    })
  }

  // Project scopes whose folder is gone (moved, renamed or deleted): their names no longer resolve.
  orphans(): { scope: string; count: number }[] {
    const n = new Map<string, number>()
    for (const e of this.read()) if (e.scope !== GLOBAL && !existsSync(e.scope)) n.set(e.scope, (n.get(e.scope) ?? 0) + 1)
    return [...n].map(([scope, count]) => ({ scope, count }))
  }
}
