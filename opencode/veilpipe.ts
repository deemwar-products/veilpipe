// Veilpipe for opencode: the same core and the same pattern layers as the Claude Code mod, a second front-end.
// Installed by `veilpipe install --opencode` as a one-line shim in ~/.config/opencode/plugins/ that re-exports this.
//
// What it covers (opencode 1.18 plugin hooks):
//   chat.message                          the person's new message (typed or pasted), before it is stored or sent
//   tool.execute.before                   deny slicing/encoding a replaced value, and writing a $NAME into code
//   tool.execute.after                    every tool's output (bash, read, grep, webfetch, MCP...) before the model
//   experimental.chat.messages.transform  backstop: everything about to be sent to the model, every call
// and the same four places in opencode 2.x (default export: setup(), see V2 below): session prompt, tool execute.before
// and execute.after, session context.
// Fails closed: if the patterns do not load, prompts are withheld, tools are refused and nothing is sent.
import { readFileSync, existsSync, statSync, watch, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compile, deepMap, merge, note, placeholderGuard, redact, scrubFile, scrubFragments, sliceGuard } from '../hooks/core.ts'
import type { Compiled, Found, PatternsFile } from '../hooks/core.ts'
import { STATE_FILES, V2_FILE_DIRS, dataDir, maskInPlace, recentFiles, scrubStore, stateDir, storePath } from './store.ts'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const MAX_SCAN_CHARS = 2_000_000
const OFF = (why: string) => `veilpipe is OFF (${why}); withheld. Fix the patterns file, then restart opencode.`

// Session state, module memory only. value -> name, so a value seen once is replaced everywhere after.
const known = new Map<string, string>()
const S = { compiled: [] as Compiled[], file: { patterns: [] } as PatternsFile, broken: undefined as string | undefined }

function readPatterns(path: string): PatternsFile | undefined {
  if (!existsSync(path)) return undefined
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    throw new Error(`${path}: ${(err as Error).message}`)
  }
}

// Shipped defaults, vendored gitleaks rules, then ~/.config/veilpipe/patterns.json, then <project>/.veilpipe/patterns.json.
export function load(directory: string, env: NodeJS.ProcessEnv = process.env) {
  const home = env.VEILPIPE_HOME ?? `${env.HOME}/.config/veilpipe`
  try {
    S.file = merge(
      readPatterns(`${ROOT}/patterns.json`),
      readPatterns(`${ROOT}/rules/gitleaks.json`),
      readPatterns(`${home}/patterns.json`),
      readPatterns(`${directory}/.veilpipe/patterns.json`),
    )
    S.compiled = compile(S.file)
    S.broken = S.compiled.length === 0 ? 'no patterns loaded' : undefined
  } catch (err) {
    S.broken = (err as Error).message
  }
  return S
}

function clean(s: string, fresh: Found[]): string {
  const r = redact(s, S.compiled, known)
  fresh.push(...r.fresh)
  return scrubFragments(r.text, known)
}

// opencode stores a running bash command's streamed output in its event log BEFORE tool.execute.after can redact it;
// once the tool is done, replace every known value in the store (and fold the WAL). bun:sqlite exists only in opencode.
async function scrubDisk(sessionID?: string, v2 = false) {
  if (known.size === 0) return
  try {
    const { Database } = await import('bun:sqlite')
    const db = new Database(storePath())
    try {
      scrubStore(db as any, known, undefined, sessionID)
    } finally {
      db.close()
    }
  } catch {
    // Never fail a turn over the store scrub; `veilpipe audit --opencode --fix` cleans what is left.
  }
  await scrubState(known)
  if (v2) {
    await scrubFilesV2(known)
    watchLogs()
  }
}

// opencode processes buffer their log lines and flush them later: on macOS (10-08) the `run` CLI's "cli starting"
// line, which records its argv (the prompt), reached the log AFTER every scrub and stayed raw. So once a value is known
// the log folder is watched, and whatever lands there is masked within ~100 ms. Only the bytes written since the last
// pass are scanned (with an overlap for a value split across writes); a new known value rescans every file once.
const watched = { on: false, sizes: new Map<string, number>(), knownSize: 0 }
export function watchLogs(dir = `${dataDir()}/log`) {
  if (watched.on) return
  watched.on = true
  let timer: ReturnType<typeof setTimeout> | undefined
  const pass = () => {
    timer = undefined
    if (known.size !== watched.knownSize) watched.sizes.clear(), (watched.knownSize = known.size)
    const overlap = 8 * Math.max(0, ...[...known.keys()].map(v => v.length))
    for (const path of recentFiles(dir, Date.now() - RECENT_MS)) {
      try {
        const from = Math.max(0, (watched.sizes.get(path) ?? 0) - overlap)
        maskInPlace(path, known, 64 * 1024 * 1024, from)
        watched.sizes.set(path, statSync(path).size)
      } catch {}
    }
  }
  try {
    const w = watch(dir, () => {
      if (timer || known.size === 0) return
      timer = setTimeout(pass, 100)
      ;(timer as any).unref?.()
    })
    ;(w as any).unref?.()
  } catch {
    watched.on = false // no log folder yet: the next scrub tries again
  }
}

const FS = { size: async (p: string) => statSync(p).size, read: async (p: string) => readFileSync(p, 'utf8'), write: async (p: string, t: string) => writeFileSync(p, t) }

// The TUI's prompt history/stash: race-safe rewrite (core scrubFile re-reads before writing, never forces).
async function scrubState(values: Map<string, string>) {
  for (const f of STATE_FILES) {
    const path = `${stateDir()}/${f}`
    if (existsSync(path)) await scrubFile(FS, path, values).catch(() => undefined)
  }
}

// 2.x shell output files and logs written in the last 15 minutes (older ones were scrubbed when they were written;
// a value first seen later is left to `veilpipe audit --opencode --fix`). Masked in place, never rewritten: other
// opencode processes append to the log the whole time (maskInPlace). Files over 64 MiB are skipped.
const RECENT_MS = 15 * 60_000
async function scrubFilesV2(values: Map<string, string>) {
  for (const d of V2_FILE_DIRS)
    for (const path of recentFiles(`${dataDir()}/${d}`, Date.now() - RECENT_MS)) {
      try {
        maskInPlace(path, values)
      } catch {}
    }
}

const size = (v: unknown) => (typeof v === 'string' ? v.length : JSON.stringify(v ?? '').length)

// Shell commands run in the 'bash' tool (1.x) or 'shell' (2.x); writes in 'write' (content) and 'edit' (newString).
function written(tool: string, args: any): { path: string; contents: string[] } | undefined {
  const path = String(args?.filePath ?? args?.path ?? '')
  if (tool === 'write' && typeof args?.content === 'string') return { path, contents: [args.content] }
  if (tool === 'edit' && typeof args?.newString === 'string') return { path, contents: [args.newString] }
  return undefined
}

// Before any tool runs (both versions): refuse when OFF, block slicing/encoding a protected value, block $NAME in code.
function guard(tool: string, args: any) {
  if (S.broken) throw new Error(OFF(S.broken))
  const names = new Set(known.values())
  const w = written(tool, args)
  if (w) {
    const why = placeholderGuard(w.path, w.contents, names)
    if (why) throw new Error(`veilpipe: this ${why}`)
  }
  if ((tool === 'bash' || tool === 'shell') && typeof args?.command === 'string') {
    const why = sliceGuard(args.command, names)
    if (why) throw new Error(`veilpipe: this command ${why}, which would print part of a protected value. Use the variable whole.`)
  }
}

export const VeilpipePlugin = async ({ directory }: { directory: string }) => {
  load(directory)
  return {
    // 1. The person's message: every text part, before opencode stores it or sends it.
    'chat.message': async (input: { sessionID?: string }, output: { parts: any[] }) => {
      if (S.broken) {
        // Nothing can be detected while OFF, so the TUI's history copy of the whole message is withheld instead.
        const typed = new Map<string, string>()
        for (const p of output.parts)
          if (p.type === 'text') {
            if (typeof p.text === 'string' && p.text.trim()) typed.set(p.text, 'VEILPIPE_OFF_MESSAGE_WITHHELD')
            p.text = OFF(S.broken)
          }
        await scrubState(typed)
        return
      }
      try {
        const fresh: Found[] = []
        let changed = false
        for (const p of output.parts)
          if (p.type === 'text' && typeof p.text === 'string') {
            const t = clean(p.text, fresh)
            if (t !== p.text) (changed = true), (p.text = t)
          }
        const first = output.parts.find(p => p.type === 'text')
        if (fresh.length > 0 && first) first.text += `\n\n${note(fresh)}`
        // Also for a value already known: the TUI just wrote this message, raw, to its prompt history again.
        if (changed) await scrubDisk(input?.sessionID)
      } catch {
        for (const p of output.parts) if (p.type === 'text') p.text = 'veilpipe failed while checking this message; withheld (fail closed).'
      }
    },

    // 2. Before a tool runs: refuse when OFF, block slicing/encoding a protected value, block $NAME literals in code.
    'tool.execute.before': async (input: { tool: string }, output: { args: any }) => guard(input.tool, output.args),

    // 3. Every tool's result, before the model sees it and before it is stored (title, output and metadata alike).
    'tool.execute.after': async (input: { sessionID?: string }, output: { title: string; output: string; metadata: any }) => {
      try {
        if (S.broken) throw new Error(S.broken)
        if (size(output.output) + size(output.metadata) > MAX_SCAN_CHARS) {
          output.output = 'veilpipe: output too large to scan for secrets; withheld.'
          output.metadata = {}
          return
        }
        const fresh: Found[] = []
        output.title = clean(output.title ?? '', fresh)
        output.output = clean(output.output ?? '', fresh)
        output.metadata = deepMap(output.metadata, s => clean(s, fresh))
        if (fresh.length > 0) output.output += `\n\n${note(fresh)}`
      } catch {
        output.output = 'veilpipe failed while redacting this result; withheld (fail closed).'
        output.metadata = {}
      }
      await scrubDisk(input?.sessionID)
    },

    // 5. At rest: when a session goes idle, scrub the store once more.
    event: async ({ event }: { event: { type: string; properties?: { sessionID?: string } } }) => {
      if (event.type === 'session.idle') await scrubDisk(event.properties?.sessionID)
    },

    // 4. Backstop on every model call: no text, reasoning or tool part goes out holding a known or matching value.
    'experimental.chat.messages.transform': async (_input: unknown, output: { messages: { parts: any[] }[] }) => {
      if (S.broken) throw new Error(OFF(S.broken))
      const fresh: Found[] = []
      for (const m of output.messages)
        for (const p of m.parts) {
          if ((p.type === 'text' || p.type === 'reasoning') && typeof p.text === 'string') p.text = clean(p.text, fresh)
          if (p.type === 'tool' && p.state) {
            if (typeof p.state.output === 'string') p.state.output = clean(p.state.output, fresh)
            if (p.state.input) p.state.input = deepMap(p.state.input, s => clean(s, fresh))
          }
        }
    },
  }
}

// opencode 2.x: hooks registered from setup(ctx) (API mapped and mutation semantics measured on 2.0.22, see
// research/opencode-v2-plugin-api.md). A rewrite of h.prompt.text / h.result / h.messages is what gets stored and sent;
// a throw in execute.before refuses the tool.
function withheld(result: any, msg: string) {
  const out = result && typeof result === 'object' ? { ...result } : {}
  out.content = [{ type: 'text', text: msg }]
  out.output = out.output && typeof out.output === 'object' ? { ...out.output, output: msg } : msg
  out.metadata = {}
  return out
}

export async function setup(ctx: any) {
  load(ctx?.location?.directory ?? process.cwd())

  // 1. The person's prompt, before it is stored or sent (also the title request, which the context hook misses).
  await ctx.session.hook('prompt', async (h: any) => {
    const text = h?.prompt?.text
    if (typeof text !== 'string') return
    if (S.broken) {
      // Nothing can be detected while OFF, so every on-disk copy of the whole message is withheld (as typed, and as
      // `run`'s argv without the quotes opencode may add around it).
      const typed = new Map<string, string>()
      for (const t of [text, text.replace(/^"([\s\S]*)"$/, '$1')]) if (t.trim()) typed.set(t, 'VEILPIPE_OFF_MESSAGE_WITHHELD')
      await scrubState(typed)
      await scrubFilesV2(typed)
      h.prompt.text = OFF(S.broken)
      return
    }
    try {
      const fresh: Found[] = []
      const t = clean(text, fresh)
      if (t === text) return
      h.prompt.text = fresh.length > 0 ? `${t}\n\n${note(fresh)}` : t
      // opencode already logged `run`'s argv and the TUI its history, both raw.
      await scrubDisk(h.sessionID, true)
    } catch {
      h.prompt.text = 'veilpipe failed while checking this message; withheld (fail closed).'
    }
  })

  // 2. Before a tool runs.
  await ctx.tool.hook('execute.before', (h: any) => guard(String(h?.tool ?? ''), h?.input))

  // 3. Every tool's result, before the model sees it and before it is stored.
  await ctx.tool.hook('execute.after', async (h: any) => {
    try {
      if (S.broken) throw new Error(S.broken)
      if (size(h.result) > MAX_SCAN_CHARS) {
        h.result = withheld(h.result, 'veilpipe: output too large to scan for secrets; withheld.')
      } else {
        const fresh: Found[] = []
        const r: any = deepMap(h.result, s => clean(s, fresh))
        if (fresh.length > 0) {
          const n = `\n\n${note(fresh)}`
          if (Array.isArray(r?.content)) r.content.push({ type: 'text', text: n })
          if (typeof r?.output === 'string') r.output += n
          else if (typeof r?.output?.output === 'string') r.output.output += n
        }
        h.result = r
      }
    } catch {
      h.result = withheld(h.result, 'veilpipe failed while redacting this result; withheld (fail closed).')
    }
    // A shell command's raw output is already on disk (shell/<project>/sh_<id>.out).
    await scrubDisk(h?.sessionID, true)
  })

  // 4. Backstop before each model call.
  await ctx.session.hook('context', (h: any) => {
    if (S.broken) throw new Error(OFF(S.broken))
    const fresh: Found[] = []
    h.messages = deepMap(h.messages, s => clean(s, fresh))
  })
}

// One file for both: opencode 1.x calls server() (or the named export), 2.x calls setup().
export default { id: 'veilpipe', server: VeilpipePlugin, setup }
