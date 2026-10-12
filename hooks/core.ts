// veilpipe core: a patterns file (regex -> $NAME) applied to text.
// Pure: no `$`, no Node. The mod, the CLI and the tests all import this file.

export type Pattern = {
  // The env-style name the value becomes: STRIPE_KEY -> "$STRIPE_KEY". Also the pattern's identity (merge, rm).
  name: string
  // A different placeholder name than the identity: vendored rules are GL_* but read as their own names.
  as?: string
  regex: string
  // Regex flags beyond the always-on "g" and "d" (e.g. "i").
  flags?: string
  // Replace only this capture group (e.g. just the password of a URL). 0 = whole match;
  // "first" = the first capture group that matched (gitleaks' rule).
  group?: number | 'first'
  // Take the name from this capture group instead (API_SECRET=... -> $API_SECRET).
  nameGroup?: number
  // What the model sees instead. "{name}" is filled in. Default "${name}" -> $STRIPE_KEY.
  replace?: string
  disabled?: boolean
  // Skip the regex unless one of these (lowercase) appears in the text: a cheap prefilter.
  keywords?: string[]
  // Minimum Shannon entropy (bits per char) of the value; below it the match is ignored.
  entropy?: number
  // Values to leave alone (see Allow).
  allow?: Allow[]
  // Where the pattern came from, e.g. "gitleaks:github-pat".
  source?: string
  // Self-tests run by `veilpipe test`: `hit` must match, `miss` must not.
  examples?: { hit?: string[]; miss?: string[] }
}

// A value is left alone when it contains a stopword (case-insensitive) or one of the regexes
// matches it. `target` widens what the regexes test: the whole match, or the line it sits on.
export type Allow = { regexes?: { regex: string; flags?: string }[]; stopwords?: string[]; target?: 'secret' | 'match' | 'line' }

export type PatternsFile = {
  patterns: Pattern[]
  // Applies to every pattern.
  allow?: Allow
  // Optional "do something": argv run once per new value, the value on stdin.
  // "{name}" in any argument is replaced by the value's name. e.g. ["my-vault", "put", "{name}"]
  onMatch?: string[]
  // Whole-text tests: `in` must rewrite to exactly `out`.
  tests?: { in: string; out: string }[]
  // The secret store: caught values are saved under their $NAME for this project (auto, default on) so later
  // commands and sessions can use them. skip: names never saved (default EMAIL; NAME_2 etc. follow their base).
  store?: { auto?: boolean; skip?: string[] }
}

export const STORE_SKIP_DEFAULT = ['EMAIL']
// Whether a caught value's name is saved: auto on (unless switched off) and its base name not skipped.
export function storeWants(file: PatternsFile, name: string): boolean {
  if (file.store?.auto === false) return false
  const base = name.replace(/_\d+$/, '')
  return !(file.store?.skip ?? STORE_SKIP_DEFAULT).includes(base)
}

// Where auto-save may take a value from (v0.2.1 bug: `head README.md` stored the README's example keys as $STRIPE_KEY,
// so a later real key would have become $STRIPE_KEY_2 and commands using $STRIPE_KEY would get the example).
// What the user types or pastes is always saved. From tool output, only the user's own environment: an env dump
// (`env`, `printenv NAME`) or a read of a .env file, optionally filtered (`| grep KEY`), and nothing else in the same
// command. Anything the parser does not model (substitutions, globs, other programs, extra files) is not a source.
const ENV_STAGE = '(local|dev|development|prod|production|staging|stage|test|testing|ci|preview|qa|uat)'
const ENV_FILE = new RegExp(`(^|/)(\\.env(\\.${ENV_STAGE})?(\\.local)?|${ENV_STAGE}\\.env)$`)
export const isEnvFile = (p: string) => ENV_FILE.test(p)

// Shell words and the operators | && ; of a plain command line, or undefined for anything else.
function shellWords(command: string): string[] | undefined {
  const c = command.replace(/\$\{HOME\}/g, '$HOME').replace(/(^|\s)(2>&1|[12]?>\s*\/dev\/null)(?=\s|$)/g, ' ')
  const out: string[] = []
  let w = ''
  let has = false
  const end = () => { if (has) out.push(w); w = ''; has = false }
  for (let i = 0; i < c.length; i++) {
    const ch = c[i]!
    if (ch === "'" || ch === '"') {
      const j = c.indexOf(ch, i + 1)
      if (j < 0) return undefined
      const inner = c.slice(i + 1, j)
      if (ch === '"' && /[`\\]|\$\(/.test(inner)) return undefined
      w += inner; has = true; i = j
    } else if (/\s/.test(ch)) end()
    else if (c.startsWith('&&', i)) { end(); out.push('&&'); i++ }
    else if (ch === '|' || ch === ';') { if (c[i + 1] === '|') return undefined; end(); out.push(ch) }
    else if (/[`\\(){}<>&*?[\]!#]/.test(ch)) return undefined
    else { w += ch; has = true }
  }
  end()
  return out
}

const FILTERS: Record<string, 'pattern' | 'numbers'> = { grep: 'pattern', rg: 'pattern', awk: 'pattern', sed: 'pattern', sort: 'numbers', head: 'numbers', tail: 'numbers', cut: 'numbers', uniq: 'numbers' }
const READERS: Record<string, 'pattern' | 'numbers' | 'files'> = { cat: 'files', source: 'files', '.': 'files', head: 'numbers', tail: 'numbers', grep: 'pattern', rg: 'pattern', sed: 'pattern', awk: 'pattern' }

// The non-flag words of one stage after its program's own argument (a grep pattern; head's counts).
function operands(kind: 'pattern' | 'numbers' | 'files', args: string[]): string[] {
  const words = args.filter(a => !a.startsWith('-'))
  if (kind === 'pattern') return words.slice(1)
  if (kind === 'numbers') return words.filter(x => !/^\d+$/.test(x))
  return words
}
const envPath = (w: string) => !/\$/.test(w.replace(/^\$HOME\//, '')) && isEnvFile(w)

export function envSource(e: { tool?: unknown; command?: unknown; file_path?: unknown }): boolean {
  if (e.tool === 'Read') return typeof e.file_path === 'string' && isEnvFile(e.file_path)
  if (e.tool !== 'Bash' || typeof e.command !== 'string') return false
  const words = shellWords(e.command)
  if (!words) return false
  // Commands (split on && and ;), each a pipeline of stages (split on |), each a list of words.
  const cmds: string[][][] = [[[]]]
  for (const w of words) {
    if (w === '&&' || w === ';') cmds.push([[]])
    else if (w === '|') cmds.at(-1)!.push([])
    else cmds.at(-1)!.at(-1)!.push(w)
  }
  let source = false
  for (const stages of cmds) {
    if (stages.some(st => st.length === 0)) return false
    const [prog, ...args] = stages[0]!
    if (stages.length === 1 && prog === 'set' && args.length === 1 && /^[-+]a$/.test(args[0]!)) continue
    if (prog === 'env' || prog === '/usr/bin/env' || prog === 'printenv') {
      if (prog !== 'printenv' ? args.length > 0 : !args.every(a => /^[A-Z_][A-Z0-9_]*$/.test(a))) return false
    } else if (prog && READERS[prog]) {
      const files = operands(READERS[prog]!, args)
      if (files.length === 0 || !files.every(envPath)) return false
    } else return false
    // Later stages only filter what came before: no file of their own.
    for (const [p, ...a] of stages.slice(1)) if (!p || !FILTERS[p] || operands(FILTERS[p]!, a).length > 0) return false
    source = true
  }
  return source
}

// A value that says it is not real: documentation and demo keys (FAKE, EXAMPLE, DEMO, your_key, xxxxxxxx...).
// A marker alone is not enough: a real password can contain 'demo' or 'sample'. It counts only when what is left,
// once the vendor prefix (sk_live_, ghp_), markers, filler words (key, password, here...) and separators are gone,
// does not look random (6+ characters mixing two of lower case, upper case, digits).
// sk_test_ is not a marker: Stripe test-mode keys are real credentials kept in .env files. Never
// auto-saved from tool output, so it cannot take a name a real key needs.
const FAKE_FILL = /x{8,}|\*{4,}|(.)\1{11,}/i
const FAKE_MARK = /fake|example|demo|dummy|sample|placeholder|changeme|redacted|your(?=[_-])/i
const FAKE_FILLER = /api|keys?|passwords?|passwd|pass|pw|secrets?|tokens?|here|test|my|value|replace|with|this|me/gi
export function looksFake(value: string): boolean {
  if (FAKE_FILL.test(value)) return true
  if (!FAKE_MARK.test(value)) return false
  const rest = value.replace(/^[a-z]{2,5}(_(live|test))?_/i, '').replace(new RegExp(FAKE_MARK.source, 'gi'), '').replace(FAKE_FILLER, '').replace(/[^A-Za-z0-9]/g, '')
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/].filter(r => r.test(rest)).length
  return !(rest.length >= 6 && kinds >= 2)
}

// Names a shell command uses: $NAME or ${NAME}.
export function referencedNames(command: string): string[] {
  return [...new Set([...command.matchAll(/\$\{?([A-Z_][A-Z0-9_]*)\}?/g)].map(m => m[1]!))]
}

// A command the model wrote that reads the store directly (the mod's own fill prefix is added after this check).
// Best effort: a disguised read still prints only $NAME, because every stored value is redacted from tool output.
export function storeReadGuard(command: string): string | undefined {
  if (/\bsecret\s+_(load|fill|save)\b/.test(command)) return 'runs veilpipe\'s internal store commands'
  if (/\bsecurity\b[^\n]*\bfind-generic-password\b/.test(command)) return 'reads the Keychain'
  if (/secrets\.enc|veilpipe\/store\/key/.test(command)) return 'reads the secret store files'
  return undefined
}

type CompiledAllow = { regexes: RegExp[]; stopwords: string[]; target: 'secret' | 'match' | 'line' }

export type Compiled = { pattern: Pattern; re: RegExp; allow: CompiledAllow[] }

export type Hit = { name: string; value: string; start: number; end: number; replace: string }

export type Found = { name: string; value: string }

// Values that point at a secret instead of being one: leave them alone. That includes a JS optional-chaining
// read like config.auth?.idp?.clientSecret: the whole value is 3+ digit-free identifiers joined by . with at least
// one ?. (generated secrets carry digits; 'Ab?.cd9Xk2Lm' stays a secret).
const REFERENCE = /^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{[A-Za-z_][A-Za-z0-9_]*\}\}|<[^>]*>|process\.env\.|os\.environ|YOUR_|x{4,}$|\*{4,}$|changeme$|(?=(?:[^.]*\.){2})[A-Za-z_$]+(?:\??\.[A-Za-z_$]+)*\?\.[A-Za-z_$]+(?:\??\.[A-Za-z_$]+)*$)/i

const NAME = /^[A-Z_][A-Z0-9_]*$/

// Later files win by name; `disabled: true` in a later file switches a pattern off.
export function merge(...files: (PatternsFile | undefined)[]): PatternsFile {
  const byName = new Map<string, Pattern>()
  let onMatch: string[] | undefined
  let store: PatternsFile['store']
  const tests: { in: string; out: string }[] = []
  const allow: Required<Pick<Allow, 'regexes' | 'stopwords'>> = { regexes: [], stopwords: [] }
  for (const f of files) {
    if (!f) continue
    for (const p of f.patterns ?? []) byName.set(p.name, { ...byName.get(p.name), ...p })
    if (f.onMatch) onMatch = f.onMatch
    if (f.store) store = { ...store, ...f.store }
    tests.push(...(f.tests ?? []))
    allow.regexes.push(...(f.allow?.regexes ?? []))
    allow.stopwords.push(...(f.allow?.stopwords ?? []))
  }
  const hasAllow = allow.regexes.length + allow.stopwords.length > 0
  return { patterns: [...byName.values()], ...(onMatch ? { onMatch } : {}), tests, ...(hasAllow ? { allow } : {}), ...(store ? { store } : {}) }
}

// Inline modifier groups ((?i:...), (?-i:...)) need Node 23+ (V8 12.5); the vendored gitleaks rules use them in 40 of
// 305 regexes. On Node 22 (the minimum we state) every such rule failed to compile, so veilpipe failed closed and
// refused every prompt (10-09). There, expandModifiers rewrites the case-insensitive parts as explicit [aA] classes.
const NATIVE_MODIFIERS = (() => {
  try {
    new RegExp('(?i:a)')
    return true
  } catch {
    return false
  }
})()

function regex(name: string, source: string, flags: string): RegExp {
  try {
    if (!NATIVE_MODIFIERS && /\(\?-?[a-z]+(?:-[a-z]+)?:/.test(source)) {
      const x = expandModifiers(source, flags)
      return new RegExp(x.source, x.flags)
    }
    return new RegExp(source, flags)
  } catch (err) {
    throw new Error(`pattern ${name}: bad regex: ${(err as Error).message}`)
  }
}

// Escape length at s[i] === '\\': \xHH, \uHHHH, \u{...}, \cX, \k<name>, \p{...}, or one character.
function escapeEnd(s: string, i: number): number {
  const n = s[i + 1]
  if (n === 'x') return i + 4
  if (n === 'u') return s[i + 2] === '{' ? s.indexOf('}', i) + 1 : i + 6
  if (n === 'c') return i + 3
  if (n === 'k' && s[i + 2] === '<') return s.indexOf('>', i) + 1
  if ((n === 'p' || n === 'P') && s[i + 2] === '{') return s.indexOf('}', i) + 1
  return i + 2
}

const other = (c: string) => {
  const l = c.toLowerCase(), u = c.toUpperCase()
  return l !== u && l.length === 1 && u.length === 1 ? (c === l ? u : l) : undefined
}

// The same regex without modifier groups or the i flag: each letter in a case-insensitive part becomes [xX], and each
// class there also gets the other case of its letters and ASCII letter ranges. Only the i modifier is supported;
// any other (m, s) throws, so the rule fails closed. Equivalence with the native form is tested over every shipped
// rule on Node 24 (test/core.node.ts).
export function expandModifiers(source: string, flags: string): { source: string; flags: string } {
  let ins = flags.includes('i')
  const stack: boolean[] = []
  let out = ''
  let i = 0
  while (i < source.length) {
    const c = source[i]!
    if (c === '\\') {
      const j = escapeEnd(source, i)
      out += source.slice(i, j)
      i = j
      continue
    }
    if (c === '[') {
      let j = i + 1
      if (source[j] === '^') j++
      const start = j
      const extra: string[] = []
      while (j < source.length && source[j] !== ']') {
        if (source[j] === '\\') {
          j = escapeEnd(source, j)
          continue
        }
        const a = source[j]!
        if (source[j + 1] === '-' && source[j + 2] !== undefined && source[j + 2] !== ']' && source[j + 2] !== '\\') {
          const b = source[j + 2]!
          for (const [lo, hi, shift] of [['a', 'z', -32], ['A', 'Z', 32]] as const) {
            const from = Math.max(a.charCodeAt(0), lo.charCodeAt(0)), to = Math.min(b.charCodeAt(0), hi.charCodeAt(0))
            if (from <= to) extra.push(`${String.fromCharCode(from + shift)}-${String.fromCharCode(to + shift)}`)
          }
          j += 3
          continue
        }
        const o = other(a)
        if (o) extra.push(o === '-' || o === '^' || o === ']' ? `\\${o}` : o)
        j++
      }
      out += source.slice(i, j) + (ins ? extra.join('') : '') + ']'
      i = j + 1
      continue
    }
    if (c === '(') {
      const m = /^\(\?([a-z]*)(?:-([a-z]*))?:/.exec(source.slice(i))
      if (m && (m[1] || m[2] !== undefined)) {
        if (/[^i]/.test((m[1] ?? '') + (m[2] ?? ''))) throw new Error(`modifier group ${m[0]} needs Node 23+ (only i is rewritten)`)
        stack.push(ins)
        if (m[1]!.includes('i')) ins = true
        if (m[2]?.includes('i')) ins = false
        out += '(?:'
        i += m[0].length
        continue
      }
      const g = /^\(\?(?:[:=!]|<[=!]|<[A-Za-z_$][\w$]*>)/.exec(source.slice(i))
      stack.push(ins)
      out += g ? g[0] : '('
      i += g ? g[0].length : 1
      continue
    }
    if (c === ')') {
      ins = stack.pop() ?? ins
      out += c
      i++
      continue
    }
    const o = ins ? other(c) : undefined
    out += o ? `[${c}${o}]` : c
    i++
  }
  return { source: out, flags: flags.replace('i', '') }
}

function compileAllow(name: string, a: Allow): CompiledAllow {
  return {
    regexes: (a.regexes ?? []).map(r => regex(name, r.regex, r.flags ?? '')),
    stopwords: (a.stopwords ?? []).map(w => w.toLowerCase()),
    target: a.target ?? 'secret',
  }
}

export function compile(file: PatternsFile): Compiled[] {
  const out: Compiled[] = []
  const global = file.allow ? [compileAllow('allow', file.allow)] : []
  for (const p of file.patterns) {
    if (p.disabled) continue
    for (const n of [p.name, p.as ?? p.name]) if (!NAME.test(n)) throw new Error(`pattern ${p.name}: name must be UPPER_SNAKE (it becomes $${n})`)
    const re = regex(p.name, p.regex, 'gd' + (p.flags ?? '').replace(/[gd]/g, ''))
    if (re.test('')) throw new Error(`pattern ${p.name}: matches the empty string`)
    out.push({ pattern: p, re, allow: [...global, ...(p.allow ?? []).map(a => compileAllow(p.name, a))] })
  }
  return out
}

// Shannon entropy in bits per character; gitleaks rules set a minimum per rule.
export function entropy(s: string): number {
  const counts = new Map<string, number>()
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of counts.values()) h -= (n / s.length) * Math.log2(n / s.length)
  return h
}

function lineAround(text: string, start: number, end: number): string {
  const from = text.lastIndexOf('\n', start - 1) + 1
  const to = text.indexOf('\n', end)
  return text.slice(from, to < 0 ? text.length : to)
}

function allowed(allow: CompiledAllow[], value: string, match: string, line: () => string): boolean {
  const lower = value.toLowerCase()
  for (const a of allow) {
    if (a.stopwords.some(w => lower.includes(w))) return true
    const target = a.target === 'match' ? match : a.target === 'line' ? line() : value
    if (a.regexes.some(r => r.test(target))) return true
  }
  return false
}

// All keywords of a pattern set in one regex, built once per set. A zero-width lookahead tries every position, so
// overlapping keywords are all seen; a shorter keyword hidden inside a longer one is recovered by substring.
const keywordIndex = new WeakMap<Compiled[], { re: RegExp; words: string[] } | null>()

function keywordsPresent(lower: string, compiled: Compiled[]): Set<string> | undefined {
  let index = keywordIndex.get(compiled)
  if (index === undefined) {
    const words = [...new Set(compiled.flatMap(c => c.pattern.keywords ?? []))].sort((a, b) => b.length - a.length)
    const escaped = words.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    index = words.length ? { re: new RegExp(`(?=(${escaped.join('|')}))`, 'g'), words } : null
    keywordIndex.set(compiled, index)
  }
  if (!index) return undefined
  const seen = new Set<string>()
  for (const m of lower.matchAll(index.re)) seen.add(m[1]!)
  const present = new Set<string>()
  for (const w of index.words) for (const f of seen) if (f.includes(w)) { present.add(w); break }
  return present
}

// No credential is an unbroken base64 run this long (a 4096-bit PEM key is wrapped at 64 chars;
// JWTs stay far below it), but embedded images are, and walking a 700 KB token with 230 regexes
// costs tens of seconds: past the hook budget. Such runs are blanked with spaces of the same
// length, so match positions are unchanged.
const BLOB = /[A-Za-z0-9+/=_-]{4097,}/g

export function maskBlobs(text: string): string {
  return text.length > 4096 ? text.replace(BLOB, m => ' '.repeat(m.length)) : text
}

// Every match of every pattern, overlaps resolved: the longest span wins, then the earlier pattern.
export function scan(input: string, compiled: Compiled[]): Hit[] {
  const text = maskBlobs(input)
  const all: (Hit & { rank: number })[] = []
  let present: Set<string> | undefined
  compiled.forEach(({ pattern, re, allow }, rank) => {
    if (pattern.keywords?.length && !pattern.keywords.some(k => (present ??= keywordsPresent(text.toLowerCase(), compiled) ?? new Set()).has(k))) return
    re.lastIndex = 0
    for (const m of text.matchAll(re)) {
      let g = pattern.group === 'first' ? m.findIndex((v, i) => i > 0 && v !== undefined && v !== '') : (pattern.group ?? 0)
      if (g < 0) g = 0
      const span = m.indices?.[g]
      const value = m[g]
      if (!span || value === undefined || value === '' || REFERENCE.test(value)) continue
      if (pattern.entropy !== undefined && entropy(value) < pattern.entropy) continue
      if (allow.length && allowed(allow, value, m[0], () => lineAround(text, m.index, m.index + m[0].length))) continue
      const named = pattern.nameGroup !== undefined ? m[pattern.nameGroup] : undefined
      const name = named ? envName(named) : (pattern.as ?? pattern.name)
      all.push({ name, value, start: span[0], end: span[1], replace: pattern.replace ?? '${name}', rank })
    }
  })
  all.sort((a, b) => b.end - b.start - (a.end - a.start) || a.rank - b.rank)
  const kept: Hit[] = []
  for (const h of all) {
    if (kept.some(k => h.start < k.end && k.start < h.end)) continue
    const { rank: _, ...hit } = h
    kept.push(hit)
  }
  return kept.sort((a, b) => a.start - b.start)
}

function envName(raw: string): string {
  return raw.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^(\d)/, '_$1')
}

// The name a value gets: the same value always gets the same name; a different
// value under a taken name gets _2, _3, ...
// `reserve` marks values that will not be saved (a README example): they never take a free base name, which stays for
// the real value the store will keep under it ($STRIPE_KEY), and get the next numbered one instead.
function nameFor(value: string, base: string, known: Map<string, string>, reserve?: (value: string) => boolean): string {
  const had = known.get(value)
  if (had) return had
  const taken = new Set(known.values())
  if (reserve?.(value) && !taken.has(base)) taken.add(base)
  let name = base
  for (let i = 2; taken.has(name); i++) name = `${base}_${i}`
  known.set(value, name)
  return name
}

function render(template: string, name: string): string {
  return template.replace(/\{name\}/g, name)
}

export type Redacted = { text: string; fresh: Found[]; hits: Hit[] }

// Rewrites `text`: pattern hits, then every value seen earlier in the session
// (`known`, value -> name, updated in place), longest first.
// Replacing a value can change what the rules see on that line (a line-level allow that held a neighbour back no longer
// applies), so redact repeats until the text is stable: the neighbour is replaced too, live and at rest alike
// (10-06: a store-wide replace on a real opencode store surfaced +325 such neighbours).
export const REDACT_PASSES = 4
export function redact(text: string, compiled: Compiled[], known: Map<string, string> = new Map(), reserve?: (value: string) => boolean): Redacted {
  const before = new Set(known.keys())
  const hits: Hit[] = []
  let out = text
  for (let i = 0; i < REDACT_PASSES; i++) {
    const r = redactOnce(out, compiled, known, reserve)
    hits.push(...r.hits)
    if (r.text === out) break
    out = r.text
  }
  const fresh: Found[] = []
  for (const [value, name] of known) if (!before.has(value)) fresh.push({ name, value })
  return { text: out, fresh, hits }
}

function redactOnce(text: string, compiled: Compiled[], known: Map<string, string>, reserve?: (value: string) => boolean): { text: string; hits: Hit[] } {
  const hits = scan(text, compiled)
  const templates = new Map<string, string>()
  let out = ''
  let at = 0
  for (const h of hits) {
    const name = nameFor(h.value, h.name, known, reserve)
    templates.set(name, h.replace)
    out += text.slice(at, h.start) + render(h.replace, name)
    at = h.end
  }
  out += text.slice(at)

  const rest = [...known].filter(([v]) => v.length >= 4).sort((a, b) => b[0].length - a[0].length)
  for (const [value, name] of rest) if (out.includes(value)) out = out.split(value).join(render(templates.get(name) ?? '${name}', name))
  return { text: out, hits }
}

// Tool output can carry a value cut up or re-encoded (`${KEY:0:12}`, base64).
// Hides any run of >= `min` characters of a known value, and its base64/hex forms.
export function scrubFragments(text: string, known: Map<string, string>, min = 8): string {
  let out = text
  for (const [value, name] of known) {
    for (const form of encodings(value)) if (out.includes(form)) out = out.split(form).join(`$${name}`)
    if (value.length < min) continue
    // Fast path: no window of `min` characters appears, so no longer one can.
    let any = false
    for (let i = 0; i + min <= value.length && !any; i++) any = out.includes(value.slice(i, i + min))
    if (!any) continue
    for (let len = value.length - 1; len >= min; len--) {
      for (let i = 0; i + len <= value.length; i++) {
        const piece = value.slice(i, i + len)
        if (out.includes(piece)) out = out.split(piece).join(`$${name}`)
      }
    }
  }
  return out
}

function encodings(value: string): string[] {
  const bytes = new TextEncoder().encode(value)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  const b64 = btoa(bin)
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('')
  return [b64, b64.replace(/=+$/, ''), hex, hex.toUpperCase()].filter(s => s.length >= 8)
}

// A Bash command that would slice, reverse or re-encode a protected variable
// prints part of the value, which whole-value scrubbing cannot catch. Returns why, or undefined.
export function sliceGuard(command: string, names: Iterable<string>): string | undefined {
  for (const n of names) {
    // ${N:0:3} ${N#x} ${N%x} ${N/x/y} ${N^^} ${N,,} ${N@Q} ${!N}... (but ${#N}, the length, is fine)
    if (new RegExp(`\\$\\{${n}\\s*[:#%/^,@]`).test(command)) return `slices or transforms $${n}`
    if (new RegExp(`\\$\\{!${n}\\b`).test(command)) return `indirects $${n}`
    // "$N" piped into a tool that cuts, reverses or encodes it.
    const use = `\\$\\{?${n}\\b\\}?`
    if (new RegExp(`${use}[^|;&\\n]*\\|\\s*(cut|rev|head|tail|fold|od|xxd|hexdump|base64|base32|sed|awk|tr|dd|perl|python3?|node|ruby)\\b`).test(command)) {
      return `pipes $${n} into a tool that can cut or encode it`
    }
    if (new RegExp(`(<<<|base64|xxd|od|rev)\\s+["']?${use}`).test(command)) return `re-encodes $${n}`
  }
  return undefined
}

// Files where a quoted "$NAME" is the literal text, not a variable: writing it there is a bug.
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|go|java|kts?|php|cs|rs|swift|scala|dart|json|jsonc|toml|ini|properties)$/i

// A Write/Edit that would put the placeholder text of a protected name into code. Returns why, or undefined.
export function placeholderGuard(filePath: string, contents: string[], names: Iterable<string>): string | undefined {
  if (!CODE_FILE.test(filePath)) return undefined
  for (const n of names) {
    const literal = new RegExp(`(['"\`])\\$\\{?${n}\\}?\\1`)
    if (contents.some(c => literal.test(c))) {
      return `writes the text $${n} into ${filePath.split('/').pop()} as if it were the value; it is only a name. Read it from the environment instead (process.env.${n}, os.environ["${n}"], os.Getenv("${n}")); the user sets ${n} outside the conversation.`
    }
  }
  return undefined
}

// Redacts every string inside a JSON-like value (a tool result of any shape).
// JSON.parse that keeps each number's source text (JSON.rawJSON, Node 22+), so writing a rewritten row back through
// JSON.stringify leaves every number exactly as it was (10-09: audit --fix turned 12345678901234567890 into
// 12345678901234567000 and 1.0 into 1). Falls back to plain JSON.parse where rawJSON is missing.
export function parseLossless(text: string): unknown {
  const J = JSON as unknown as { rawJSON?: (s: string) => unknown }
  if (typeof J.rawJSON !== 'function') return JSON.parse(text)
  const raw = J.rawJSON
  return (JSON.parse as (t: string, r: (k: string, v: unknown, c?: { source?: string }) => unknown) => unknown)(text, (_k, v, c) =>
    typeof v === 'number' && c?.source !== undefined ? raw(c.source) : v)
}

export function deepMap(v: unknown, f: (s: string) => string): unknown {
  if (typeof v === 'string') return f(v)
  if (Array.isArray(v)) return v.map(x => deepMap(x, f))
  if (v && typeof v === 'object' && (JSON as unknown as { isRawJSON?: (x: unknown) => boolean }).isRawJSON?.(v)) return v
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(v)) o[k] = deepMap(x, f)
    return o
  }
  return v
}

// A transcript file (JSONL) still holding a known value: a raw value and its
// JSON-escaped form are both replaced. Returns the same string when nothing matched.
export function scrubJsonl(text: string, known: Map<string, string>): string {
  let out = text
  for (const [value, name] of [...known].sort((a, b) => b[0].length - a[0].length)) {
    const escaped = JSON.stringify(value).slice(1, -1)
    for (const form of new Set([value, escaped])) if (out.includes(form)) out = out.split(form).join(`$${name}`)
  }
  return out
}

// The file operations scrubFile needs; the mod passes $.fs, tests pass a fake.
export type FileOps = {
  size: (path: string) => Promise<number>
  read: (path: string) => Promise<string>
  write: (path: string, text: string) => Promise<void>
}

export type ScrubResult = 'clean' | 'scrubbed' | 'too-large' | 'busy'

// Rewrites a JSONL file without the known values. The file may be shared and appended to by
// other sessions (history.jsonl), so it is read twice and written only if nothing changed in
// between; a lost race is retried, never forced.
export async function scrubFile(fs: FileOps, path: string, known: Map<string, string>, maxBytes = 4 * 1024 * 1024, attempts = 3): Promise<ScrubResult> {
  if ((await fs.size(path)) > maxBytes) return 'too-large'
  for (let i = 0; i < attempts; i++) {
    const text = await fs.read(path)
    const clean = scrubJsonl(text, known)
    if (clean === text) return 'clean'
    if ((await fs.read(path)) !== text) continue
    await fs.write(path, clean)
    return 'scrubbed'
  }
  return 'busy'
}

export type TestResult = { ok: boolean; label: string; detail?: string }

// The suite `veilpipe test` runs: each pattern's examples, then the whole-text tests.
export function runTests(file: PatternsFile): TestResult[] {
  const results: TestResult[] = []
  let compiled: Compiled[]
  try {
    compiled = compile(file)
  } catch (err) {
    return [{ ok: false, label: 'compile', detail: (err as Error).message }]
  }
  for (const c of compiled) {
    const only = [c]
    for (const s of c.pattern.examples?.hit ?? []) {
      const hits = scan(s, only)
      results.push({ ok: hits.length > 0, label: `${c.pattern.name} hits ${JSON.stringify(s)}` })
    }
    for (const s of c.pattern.examples?.miss ?? []) {
      const hits = scan(s, only)
      results.push({ ok: hits.length === 0, label: `${c.pattern.name} misses ${JSON.stringify(s)}`, ...(hits[0] ? { detail: `matched ${JSON.stringify(hits[0].value)}` } : {}) })
    }
  }
  for (const t of file.tests ?? []) {
    const got = redact(t.in, compiled).text
    results.push({ ok: got === t.out, label: `rewrite ${JSON.stringify(t.in)}`, ...(got !== t.out ? { detail: `got ${JSON.stringify(got)}` } : {}) })
  }
  return results
}

// Argv for the onMatch command, "{name}" filled in.
export function onMatchArgv(argv: string[], name: string): string[] {
  return argv.map(a => a.replace(/\{name\}/g, name))
}

// The note the model gets beside a rewritten prompt or tool result. fillable: names the store holds, which a Bash
// command fills in when it runs; for any other name the note says plainly that commands cannot use it.
// via 'exec': the host fills nothing into commands itself (opencode), so a stored value is reached only through
// `veilpipe exec`, which fills the names a command uses from the store and scrubs its output.
export function note(fresh: Found[], fillable: Set<string> = new Set(), via: 'fill' | 'exec' = 'fill'): string {
  const names = fresh.map(f => `$${f.name}`).join(', ')
  const can = fresh.filter(f => fillable.has(f.name)).map(f => f.name)
  const cannot = fresh.filter(f => !fillable.has(f.name)).map(f => `$${f.name}`)
  const one = can[0] ?? fresh[0]?.name ?? 'NAME'
  return (
    `veilpipe replaced ${fresh.length} sensitive value${fresh.length === 1 ? '' : 's'} with ${names} before you saw ${fresh.length === 1 ? 'it' : 'them'}. ` +
    (can.length ? `${can.map(n => `$${n}`).join(', ')} ${can.length === 1 ? 'is' : 'are'} in the user's local secret store: write ${can.length === 1 ? 'it' : 'them'} as shell variables in Bash ("$${one}") and the value is filled in when the command runs. ` : '') +
    (cannot.length && via === 'exec' ? `${cannot.join(', ')} ${cannot.length === 1 ? 'is' : 'are'} not filled into commands here. If a command needs one, ask the user to run \`veilpipe secret add ${cannot[0]!.slice(1)}\` themselves if it is not stored yet (never to paste the value here), then run the command as \`veilpipe exec '<command using $${cannot[0]!.slice(1)}>'\`: it fills stored names in and hides them in the output. ` : '') +
    (cannot.length && via === 'fill' ? `${cannot.join(', ')} ${cannot.length === 1 ? 'is' : 'are'} not available to commands; if one is needed, ask the user to run \`veilpipe secret add ${cannot[0]!.slice(1)}\` themselves (never to paste the value here). ` : '') +
    `In code, read values from the environment (process.env.${one}, os.environ["${one}"]); never write the text $${one} into a file, it is not the value. ` +
    'Do not ask the user to paste a value again, and do not try to print, slice or encode it.'
  )
}
