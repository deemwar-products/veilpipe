import type { EngineInterface, Register } from 'claude-code'

import { compile, deepMap, merge, note, onMatchArgv, placeholderGuard, redact, referencedNames, scrubFile, scrubFragments, scrubJsonl, sliceGuard, storeReadGuard, storeWants } from './core'
import type { Compiled, Found, PatternsFile } from './core'

// Tool output bigger than this is not scanned in time; it is withheld instead.
const MAX_SCAN_CHARS = 2_000_000

// Session state, module memory only: never in the transcript, never sent to a model.
// value -> name, so a value seen once is replaced everywhere after.
const known = new Map<string, string>()
const S = {
  compiled: [] as Compiled[],
  file: { patterns: [] } as PatternsFile,
  // Set when the patterns did not load: every prompt is refused until fixed (fail closed).
  broken: undefined as string | undefined,
  home: '',
  replaced: 0,
  // The secret store: this project's scope, and the names it holds (a Bash command using one gets it filled in).
  scope: undefined as string | undefined,
  stored: new Set<string>(),
  // Values loaded from the store (value -> name) and the names already explained to the model this session.
  seeded: new Map<string, string>(),
  announced: new Set<string>(),
  noticed: false,
}

async function readPatterns($: EngineInterface, path: string): Promise<PatternsFile | undefined> {
  if (!(await $.fs.exists(path))) return undefined
  try {
    return JSON.parse(await $.fs.read(path))
  } catch (err) {
    throw new Error(`${path}: ${(err as Error).message}`)
  }
}

let loaded: Promise<void> | undefined
// Loads once per module load, on first use; /veilpipe reload loads again.
function ready($: EngineInterface): Promise<void> {
  return (loaded ??= load($))
}

// Shipped defaults, vendored gitleaks rules, then ~/.config/veilpipe/patterns.json, then ./.veilpipe/patterns.json.
async function load($: EngineInterface) {
  const env = await $.env.get('VEILPIPE_HOME')
  const userHome = await $.env.get('HOME')
  S.home = env ?? `${userHome}/.config/veilpipe`
  try {
    const cwd = await $.session.cwd()
    S.file = merge(
      await readPatterns($, `${$.plugin.root}/patterns.json`),
      await readPatterns($, `${$.plugin.root}/rules/gitleaks.json`),
      await readPatterns($, `${S.home}/patterns.json`),
      await readPatterns($, `${cwd}/.veilpipe/patterns.json`),
    )
    S.compiled = compile(S.file)
    S.broken = S.compiled.length === 0 ? 'no patterns loaded' : undefined
  } catch (err) {
    S.broken = (err as Error).message
  }
  await loadStore($)
}

const cli = ($: EngineInterface) => `${$.plugin.root}/bin/veilpipe`

// This project's stored values seed `known`, so a value stored before keeps its name here and a new value gets the
// next free one (the name the store will take). Without the store, redaction works exactly as before.
async function loadStore($: EngineInterface) {
  S.scope = undefined
  S.stored.clear()
  S.seeded.clear()
  if (S.file.store?.auto === false || (await $.env.get('VEILPIPE_NO_STORE'))) return
  try {
    const r = await $.process.run([cli($), 'secret', '_load', await $.session.cwd()], { timeoutMs: 15_000 })
    if (r.exitCode !== 0) throw new Error(`exit ${r.exitCode}`)
    const { scope, entries } = JSON.parse(r.stdout) as { scope: string; entries: [string, string][] }
    S.scope = scope
    for (const [value, name] of entries) {
      if (!known.has(value)) known.set(value, name)
      S.seeded.set(value, name)
      S.stored.add(name)
    }
  } catch (err) {
    $.ui.log(`veilpipe: secret store not loaded (${(err as Error).message}); values are replaced but not saved`, { to: 'debug' })
  }
}

// Saves newly caught values under the names the model is about to see. Never throws: a failed save only means the
// value is not fillable, which the note then says.
async function autoSave($: EngineInterface, fresh: Found[]) {
  if (!S.scope) return
  for (const f of fresh) {
    if (!storeWants(S.file, f.name) || S.stored.has(f.name)) continue
    try {
      const r = await $.process.run([cli($), 'secret', '_save', S.scope, f.name], { stdin: f.value, timeoutMs: 15_000 })
      const how = r.stdout.trim()
      if (r.exitCode === 0 && (how === 'saved' || how === 'first' || how === 'exists')) S.stored.add(f.name)
      else $.ui.log(`veilpipe: $${f.name} not saved (${how || `exit ${r.exitCode}`})`, { to: 'debug' })
      if (how === 'first' && !S.noticed) {
        S.noticed = true
        $.ui.toast(`veilpipe: saved $${f.name} to your local secret store for this project, so later commands can use it. See: veilpipe secret ls. Turn off: "store": { "auto": false } in patterns.json.`)
      }
    } catch {
      $.ui.log(`veilpipe: $${f.name} not saved`, { to: 'debug' })
    }
  }
}

// A stored value is in `known` from the start, so it is never fresh; the first time one appears this session the
// model still gets the note for its name.
function seenStored(text: string): Found[] {
  const out: Found[] = []
  for (const [value, name] of S.seeded) if (!S.announced.has(name) && text.includes(value)) out.push({ name, value })
  return out
}
function toAnnounce(fresh: Found[], text: string): Found[] {
  const all = [...fresh, ...seenStored(text)]
  for (const f of all) S.announced.add(f.name)
  return all
}

const shq = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`

// A Bash command that uses stored names first fetches their values from the store, in the child process: the
// value is never in the command text the model wrote, the transcript or the model's context. A failed fetch stops
// the command (exit 97) rather than run it with an empty value.
function withFill($: EngineInterface, command: string): string {
  const names = referencedNames(command).filter(n => S.stored.has(n))
  if (!S.scope || names.length === 0) return command
  return `__vp=$(${shq(cli($))} secret _fill ${shq(S.scope)} ${names.join(' ')}) || exit 97; eval "$__vp"; unset __vp\n${command}`
}

function status($: EngineInterface) {
  if (S.broken) return $.ui.status(`OFF (${S.broken}), prompts refused`)
  $.ui.status(`${S.compiled.length} patterns · ${S.replaced} replaced`)
}

// The "do something": run the user's onMatch command once per new value, value on stdin.
// Fire-and-forget, so a slow or failing command never holds or opens a hook.
function sideEffects($: EngineInterface, fresh: Found[]) {
  S.replaced += fresh.length
  status($)
  const argv = S.file.onMatch
  if (!argv || argv.length === 0) return
  for (const f of fresh) {
    $.process
      .run(onMatchArgv(argv, f.name), { stdin: f.value, timeoutMs: 10_000 })
      .then(r => (r.exitCode === 0 ? undefined : $.ui.toast(`veilpipe: onMatch exited ${r.exitCode} for $${f.name}`)))
      .catch(() => $.ui.toast(`veilpipe: onMatch could not run for $${f.name}`))
  }
}

// Pure: every string of a tool result through the patterns, known values and their fragments.
function redactResult(result: unknown): { result: unknown; fresh: Found[]; changed: boolean } {
  const fresh: Found[] = []
  let changed = false
  const out = deepMap(result, s => {
    const r = redact(s, S.compiled, known)
    fresh.push(...r.fresh)
    const t = scrubFragments(r.text, known)
    if (t !== s) changed = true
    return t
  })
  return { result: out, fresh, changed }
}

function size(v: unknown): number {
  return typeof v === 'string' ? v.length : JSON.stringify(v ?? '').length
}

// ~/.claude/projects/<cwd with / and . as ->/<session>.jsonl
async function transcriptPath($: EngineInterface): Promise<string | undefined> {
  const dir = await configDir($)
  const id = await $.session.id()
  for (const cwd of new Set([await $.session.root(), await $.session.cwd()])) {
    const path = `${dir}/projects/${cwd.replace(/[^A-Za-z0-9]/g, '-')}/${id}.jsonl`
    if (await $.fs.exists(path)) return path
  }
  return undefined
}

// $.fs.read refuses files over 4 MiB; scrubFile (core) skips anything larger.
async function scrubOne($: EngineInterface, path: string, label: string) {
  const ops = { size: async (p: string) => (await $.fs.stat(p)).size, read: (p: string) => $.fs.read(p), write: (p: string, t: string) => $.fs.write(p, t) }
  let r: string = await scrubFile(ops, path, known)
  if (r === 'too-large') {
    // Over the engine's 4 MiB read limit: the CLI rewrites it in a child process instead.
    const { exitCode, stdout } = await $.process.run([`${$.plugin.root}/bin/veilpipe`, 'scrub-file', path], { stdin: JSON.stringify([...known]), timeoutMs: 60_000 })
    r = exitCode === 0 ? stdout.trim() : 'failed'
    if (r === 'failed') $.ui.log(`veilpipe: could not scrub ${label} (over 4 MB)`, { to: 'debug' })
  }
  if (r === 'busy') $.ui.log(`veilpipe: ${label} kept changing; not scrubbed this time`, { to: 'debug' })
}

async function configDir($: EngineInterface): Promise<string> {
  return (await $.env.get('CLAUDE_CONFIG_DIR')) ?? `${await $.env.get('HOME')}/.claude`
}

// Values the hooks never saw still reach disk: `claude -p` writes the raw prompt as a
// queue-operation row before prompt.submit runs, and the interactive composer writes what was
// typed to history.jsonl (up-arrow recall) before any hook. Both are scrubbed after each turn.
async function scrubDisk($: EngineInterface) {
  if (known.size === 0) return
  const transcript = await transcriptPath($)
  if (transcript) {
    await scrubOne($, transcript, 'the transcript')
    // This session's subagents write their own transcripts beside it: <session>/subagents/agent-*.jsonl.
    const subs = `${transcript.slice(0, -'.jsonl'.length)}/subagents`
    if (await $.fs.exists(subs))
      for (const e of await $.fs.list(subs))
        if (e.kind === 'file' && e.name.endsWith('.jsonl')) await scrubOne($, `${subs}/${e.name}`, `subagent transcript ${e.name}`)
  }
  const history = `${await configDir($)}/history.jsonl`
  if (await $.fs.exists(history)) await scrubOne($, history, 'history.jsonl')
}

// The file a write-type tool targets and the text it would put there.
function writtenContent(e: any): { path: string; contents: string[] } | undefined {
  const path = e.file_path ?? e.notebook_path
  if (typeof path !== 'string') return undefined
  const contents = [e.content, e.new_string, e.new_source, ...(Array.isArray(e.edits) ? e.edits.map((x: any) => x?.new_string) : [])]
  const strings = contents.filter((x): x is string => typeof x === 'string')
  return strings.length ? { path, contents: strings } : undefined
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await ready($)
    await $.command.register({ name: 'veilpipe', description: 'veilpipe: status | reload' })
    status($)
    return next(e)
  })

  on('command.run', { command: 'veilpipe' }, async ($, e) => {
    if (e.args.trim() === 'reload') await (loaded = load($))
    else await ready($)
    status($)
    if (S.broken) return { text: `veilpipe is OFF: ${S.broken}. Prompts are refused until the patterns load (fix, then /veilpipe reload).` }
    const names = [...new Set(known.values())].map(n => `$${n}`).join(', ') || 'none yet'
    return { text: `${S.compiled.length} patterns; replaced this session: ${names}.` }
  })

  // 1. What the person types or pastes, before it is queued for the model.
  on('prompt.submit', async ($, e, next) => {
    await ready($)
    if (S.broken) return { drop: `veilpipe is OFF (${S.broken}); prompt not sent. Fix the patterns, then /veilpipe reload.` }
    const r = redact(e.text, S.compiled, known)
    if (r.fresh.length === 0 && r.text === e.text) return next(e)
    sideEffects($, r.fresh)
    await autoSave($, r.fresh)
    const tell = toAnnounce(r.fresh, e.text)
    const context = tell.length > 0 ? [...(e.context ?? []), note(tell, S.stored)] : e.context
    return next({ ...e, text: r.text, ...(context ? { context } : {}) })
  }).catch(() => ({ drop: 'veilpipe failed while checking this prompt; it was not sent (fail closed).' }))

  // 2. Every tool call: block slicing of a replaced value, then redact the result.
  on('tool.call', async ($, e, next) => {
    await ready($)
    if (S.broken) return { deny: `veilpipe is OFF (${S.broken}); tool not run.` }
    const writes = writtenContent(e)
    if (writes) {
      const why = placeholderGuard(writes.path, writes.contents, new Set(known.values()))
      if (why) return { deny: `veilpipe: this ${why}` }
    }
    if (e.tool === 'Bash') {
      const why = sliceGuard(e.command, new Set(known.values()))
      if (why) return { deny: `veilpipe: this command ${why}, which would print part of a protected value. Use the variable whole.` }
      const reads = storeReadGuard(e.command)
      if (reads) return { deny: `veilpipe: this command ${reads}. Use $NAME in the command instead; veilpipe fills it in.` }
    }
    const ran = await next(e.tool === 'Bash' && typeof e.command === 'string' ? { ...e, command: withFill($, e.command) } : e)
    // Pure from here: no I/O may sit between the raw result and what we return.
    if (ran.deny !== undefined) return ran
    if (size(ran.result) > MAX_SCAN_CHARS) return { result: 'veilpipe: output too large to scan for secrets; withheld.', isError: true } as typeof ran
    const r = redactResult(ran.result)
    if (!r.changed) return ran
    sideEffects($, r.fresh)
    await autoSave($, r.fresh)
    const tell = S.seeded.size ? toAnnounce(r.fresh, JSON.stringify(ran.result)) : r.fresh
    return { result: r.result, ...(ran.isError ? { isError: true } : {}), ...(tell.length > 0 ? { context: [note(tell, S.stored)] } : {}) } as typeof ran
  }).catch(async ($, e, next) => {
    // Never run a tool whose check failed; if it already ran, hand back only a redacted result.
    if (!next.called) return { deny: 'veilpipe failed while checking this tool call; it was not run (fail closed).' } as any
    try {
      const ran = await next(e)
      if (ran.deny !== undefined) return ran
      return { result: redactResult(ran.result).result, ...(ran.isError ? { isError: true } : {}) } as typeof ran
    } catch {
      return { result: 'veilpipe failed while redacting this result; withheld (fail closed).', isError: true } as any
    }
  })

  // 3. Text the engine injects by itself: @-files, "file changed on disk" notices, hook output.
  on('prompt.attachment', async ($, e, next) => {
    await ready($)
    const r = redact(e.text, S.compiled, known)
    if (r.fresh.length > 0) sideEffects($, r.fresh)
    return next(r.text === e.text ? e : { ...e, text: r.text })
  }).catch(($, e, next) => next({ ...e, text: '[veilpipe withheld this attachment: the secret check failed]' }))

  // 4. Belt and braces: no stored row keeps a value already replaced elsewhere.
  on('session.append', async ($, e, next) => {
    if (known.size === 0) return next(e)
    let changed = false
    const content = e.message.content.map(b => {
      if (b.type === 'text' && typeof b.text === 'string') {
        const t = scrubJsonl(b.text, known)
        if (t !== b.text) return (changed = true), { ...b, text: t }
      }
      return b
    })
    return next(changed ? { ...e, message: { ...e.message, content } } : e)
  })

  // 5. On disk: scrub the transcript and history.jsonl after each turn and at the end.
  on('turn.complete', async ($, e, next) => {
    const done = await next(e)
    await scrubDisk($).catch(() => $.ui.log('veilpipe: disk scrub failed', { to: 'debug' }))
    return done
  })

  on('session.end', async ($, e, next) => {
    await scrubDisk($).catch(() => $.ui.log('veilpipe: disk scrub failed', { to: 'debug' }))
    return next(e)
  })
}
