// node --test test/opencode.node.ts : the opencode front-end (plugin hooks + SQLite store scrub). FAKE values only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import veilpipe, { VeilpipePlugin, load, setup } from '../opencode/veilpipe.ts'
import { findInStore, fixStore, redactCell, scrubStore } from '../opencode/store.ts'
import { compile, merge } from '../hooks/core.ts'

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite')
const KEY = 'sk_test_DEMO0000FAKE0000FAKE0000aa'
const PW = 'FakeDbPw-0000x'
const dir = mkdtempSync(join(tmpdir(), 'vp-oc-'))
process.env.VEILPIPE_HOME = join(dir, 'home') // no user layer
process.env.OPENCODE_DB = join(dir, 'none.db') // the live scrub never touches a real store from a test
process.env.XDG_STATE_HOME = join(dir, 'state')
process.env.XDG_DATA_HOME = join(dir, 'data')

test('chat.message: the typed key becomes $STRIPE_KEY, with the note', async () => {
  const h = await VeilpipePlugin({ directory: dir })
  const out = { parts: [{ type: 'text', text: `deploy with ${KEY}` }, { type: 'file', url: 'x' }] }
  await h['chat.message']({}, out)
  assert.match(out.parts[0]!.text!, /^deploy with \$STRIPE_KEY\n\nveilpipe replaced/)
  assert.ok(!JSON.stringify(out).includes(KEY))
})

test('tool.execute.after: output, title and metadata (bash streams output into metadata) are all redacted', async () => {
  const h = await VeilpipePlugin({ directory: dir })
  const out = { title: 'cat secret.env', output: `DB_PASSWORD=${PW}\n`, metadata: { output: `DB_PASSWORD=${PW}\n`, exit: 0 } }
  await h['tool.execute.after']({}, out)
  assert.ok(!JSON.stringify(out).includes(PW))
  assert.match(out.output, /DB_PASSWORD=\$DB_PASSWORD/)
  assert.equal(out.metadata.exit, 0)
})

test('tool.execute.before: slicing or encoding a replaced value is refused; $NAME literal into code is refused', async () => {
  const h = await VeilpipePlugin({ directory: dir })
  await h['chat.message']({}, { parts: [{ type: 'text', text: `key ${KEY}` }] })
  await assert.rejects(h['tool.execute.before']({ tool: 'bash' }, { args: { command: 'echo ${STRIPE_KEY:0:8}' } }), /slices or transforms/)
  await assert.rejects(h['tool.execute.before']({ tool: 'bash' }, { args: { command: 'echo $STRIPE_KEY | base64' } }), /cut or encode/)
  await assert.rejects(h['tool.execute.before']({ tool: 'write' }, { args: { filePath: 'a.js', content: 'const k = "$STRIPE_KEY"' } }), /veilpipe/)
  await h['tool.execute.before']({ tool: 'bash' }, { args: { command: 'curl -H "Authorization: Bearer $STRIPE_KEY" x' } })
})

test('backstop transform: nothing about to be sent holds a raw value', async () => {
  const h = await VeilpipePlugin({ directory: dir })
  const out = { messages: [{ parts: [{ type: 'text', text: `pw ${PW}` }, { type: 'tool', state: { input: { command: `echo ${KEY}` }, output: KEY } }] }] }
  await h['experimental.chat.messages.transform']({}, out)
  assert.ok(!JSON.stringify(out).includes(KEY) && !JSON.stringify(out).includes(PW))
})

test('fail closed: a broken patterns file withholds the message, refuses tools and blocks the model call', async () => {
  const bad = join(dir, 'bad'); mkdirSync(join(bad, '.veilpipe'), { recursive: true })
  writeFileSync(join(bad, '.veilpipe', 'patterns.json'), '{ broken')
  const h = await VeilpipePlugin({ directory: bad })
  const hist = join(dir, 'state', 'opencode', 'prompt-history.jsonl')
  mkdirSync(join(dir, 'state', 'opencode'), { recursive: true })
  writeFileSync(hist, JSON.stringify({ input: `key ${KEY}` }) + '\n')
  const msg = { parts: [{ type: 'text', text: `key ${KEY}` }] }
  await h['chat.message']({}, msg)
  assert.match(msg.parts[0]!.text, /veilpipe is OFF/)
  assert.ok(!readFileSync(hist, 'utf8').includes(KEY), 'TUI history keeps the raw message while OFF')
  await assert.rejects(h['tool.execute.before']({ tool: 'bash' }, { args: { command: 'ls' } }), /OFF/)
  const after = { title: '', output: KEY, metadata: { output: KEY } }
  await h['tool.execute.after']({}, after)
  assert.ok(!JSON.stringify(after).includes(KEY))
  await assert.rejects(h['experimental.chat.messages.transform']({}, { messages: [] }), /OFF/)
  load(dir) // restore for later tests
})

function store() {
  const db = new DatabaseSync(':memory:')
  db.exec('create table part (id text, data text); create table event (id text, seq integer, data text)')
  db.prepare('insert into part values (?, ?)').run('p1', JSON.stringify({ type: 'tool', state: { output: `STRIPE_KEY=${KEY}\nDB_PASSWORD=${PW}\n` } }))
  db.prepare('insert into event values (?, ?, ?)').run('e1', 1, JSON.stringify({ metadata: { output: `DB_PASSWORD=${PW}` } }))
  return db
}

test('store: findInStore reads JSON cells string by string and finds both values', () => {
  const { found, cells } = findInStore(store(), compile(merge(load(dir).file)))
  assert.deepEqual([...found.entries()].sort(), [[KEY, 'STRIPE_KEY'], [PW, 'DB_PASSWORD']].sort())
  assert.equal(cells, 2)
})

test('store: scrubStore replaces raw and JSON-escaped forms in every text column, rows stay valid JSON', () => {
  const db = store()
  const quoted = 'Fake"Quote\\0000x' // a value with characters JSON escapes
  db.prepare('insert into part values (?, ?)').run('p2', JSON.stringify({ text: `pw ${quoted}` }))
  const n = scrubStore(db, new Map([[KEY, 'STRIPE_KEY'], [PW, 'DB_PASSWORD'], [quoted, 'PASSWORD']]))
  assert.ok(n >= 3)
  for (const { data } of db.prepare('select data from part union all select data from event').all()) {
    assert.ok(!data.includes(KEY) && !data.includes(PW) && !data.includes(JSON.stringify(quoted).slice(1, -1)), data)
    JSON.parse(data)
  }
  assert.equal(scrubStore(db, new Map()), 0)
})

test('chat.message also scrubs the TUI prompt history, which the client wrote before the server saw the message', async () => {
  const hist = join(dir, 'state', 'opencode', 'prompt-history.jsonl')
  mkdirSync(join(dir, 'state', 'opencode'), { recursive: true })
  writeFileSync(hist, JSON.stringify({ input: 'older line' }) + '\n' + JSON.stringify({ input: `ship it with ${KEY}` }) + '\n')
  const h = await VeilpipePlugin({ directory: dir })
  await h['chat.message']({}, { parts: [{ type: 'text', text: `ship it with ${KEY}` }] })
  const after = readFileSync(hist, 'utf8')
  assert.ok(!after.includes(KEY))
  assert.match(after, /older line[\s\S]*ship it with \$STRIPE_KEY/)
})

// A real 10-06 --fix failed with a FOREIGN KEY error after partly rewriting the store, and would have replaced
// opencode's own login tokens/credentials. These run on opencode's real 1.18 schema with foreign keys enforced.
function realStore() {
  const db = new DatabaseSync(':memory:')
  db.exec('pragma foreign_keys = ON')
  db.exec(readFileSync(new URL('./fixtures/opencode-1.18-schema.sql', import.meta.url), 'utf8'))
  const SID = 'ses_FAKEsk_test_DEMO0000FAKE0000FAKE00ID' // a secret-SHAPED id: must never be touched
  db.prepare("insert into project (id, worktree, time_created, time_updated, sandboxes) values ('prj', '/w', 0, 0, '[]')").run()
  db.prepare("insert into session (id, project_id, slug, directory, title, version, time_created, time_updated) values (?, 'prj', 's', '/w', ?, '1', 0, 0)").run(SID, `deploy ${KEY}`)
  db.prepare("insert into message (id, session_id, time_created, time_updated, data) values ('msg1', ?, 0, 0, ?)").run(SID, JSON.stringify({ text: `key ${KEY}` }))
  db.prepare("insert into part (id, message_id, session_id, time_created, time_updated, data) values ('prt1', 'msg1', ?, 0, 0, ?)").run(SID, JSON.stringify({ type: 'tool', state: { output: `DB_PASSWORD=${PW}\nSTRIPE_KEY=${KEY}\nAPI_TOKEN=${PW}Z9` } }))
  db.prepare("insert into account (id, email, url, access_token, refresh_token, time_created, time_updated) values ('acc', 'a@example.com', 'u', ?, ?, 0, 0)").run(`sk-FAKEaccess${'0'.repeat(24)}`, `token=${PW}`)
  db.prepare("insert into credential (id, label, value, time_created, time_updated) values ('cred', 'stripe', ?, 0, 0)").run(KEY)
  return { db, SID }
}

test('fixStore on the real schema: conversation scrubbed in one transaction, ids and opencode credentials untouched, re-audit 0', () => {
  const { db, SID } = realStore()
  const compiled = compile(merge(load(dir).file))
  const r = fixStore(db, compiled)
  assert.ok(r.before >= 2 && r.after === 0 && r.changed > 0, JSON.stringify(r))
  assert.equal(db.prepare('pragma foreign_key_check').all().length, 0)
  assert.equal(db.prepare('select id from session').get().id, SID)
  assert.equal(db.prepare('select value from credential').get().value, KEY) // opencode's own store: left alone
  assert.match(db.prepare('select refresh_token from account').get().refresh_token, new RegExp(PW))
  for (const { data } of db.prepare('select data from message union all select data from part').all()) {
    assert.ok(!data.includes(KEY) && !data.includes(PW), data)
    JSON.parse(data)
  }
  // the longer value (PW + 'Z9') was replaced whole, not left as a '$DB_PASSWORDZ9' fragment
  assert.ok(!db.prepare('select data from part').get().data.includes('$DB_PASSWORDZ9'))
  assert.ok(!db.prepare('select title from session').get().title.includes(KEY))
})

test('fixStore: any error mid-way rolls back EVERYTHING (no partial rewrite)', () => {
  const { db } = realStore()
  db.exec("create trigger boom before update on part begin select raise(abort, 'injected failure'); end")
  const before = db.prepare('select data from message').get().data
  assert.throws(() => fixStore(db, compile(merge(load(dir).file))), /injected failure/)
  assert.equal(db.prepare('select data from message').get().data, before)
  assert.match(db.prepare('select title from session').get().title, new RegExp(KEY))
})

test('fixStore: a rewrite that would create new matches is rolled back', () => {
  const { db } = realStore()
  // A value whose $NAME replacement leaves the cell matching something new: force it with a hostile pattern set
  // that also flags any $NAME, so the re-audit goes UP and the transaction must roll back.
  const c = compile(merge({ patterns: [{ name: 'STRIPE_KEY', regex: 'sk_test_[A-Za-z0-9]{20,}' }, { name: 'DOLLAR_ANY', regex: '\\$([A-Z_]{6,})', group: 1 }] }))
  const before = db.prepare('select data from part').get().data
  assert.throws(() => fixStore(db, c), /rolled back/)
  assert.equal(db.prepare('select data from part').get().data, before)
})

test('veilpipe audit --opencode --fix on a COPY of a real-shaped store file: FK integrity kept, 0 changes outside the content columns', async () => {
  const { main } = await import('../cli/veilpipe.ts')
  const { CONTENT_COLUMNS } = await import('../opencode/store.ts')
  const d = mkdtempSync(join(tmpdir(), 'vp-oc-copy-'))
  const orig = join(d, 'opencode.db'), copy = join(d, 'copy.db')
  const { db: mem } = realStore()
  mem.exec(`vacuum into '${orig}'`)
  const o = new DatabaseSync(orig); o.exec(`vacuum into '${copy}'`); o.close()
  // every row of every table with the allowlisted content columns blanked out: must be byte-identical after --fix
  const shape = (path: string) => {
    const db = new DatabaseSync(path)
    const out: Record<string, unknown[]> = {}
    for (const { name } of db.prepare("select name from sqlite_master where type='table' order by name").all() as any[]) {
      const keep = new Set(CONTENT_COLUMNS.filter(([t]) => t === name).map(([, c]) => c))
      out[name] = (db.prepare(`select * from "${name}" order by rowid`).all() as any[]).map(r => Object.fromEntries(Object.entries(r).filter(([k]) => !keep.has(k))))
    }
    db.close()
    return out
  }
  const before = shape(copy)
  const env = { OPENCODE_DB: process.env.OPENCODE_DB, XDG_STATE_HOME: process.env.XDG_STATE_HOME }
  process.env.OPENCODE_DB = copy
  process.env.XDG_STATE_HOME = join(d, 'state') // empty: the real prompt history is never touched by a copy run
  const lines: string[] = []
  try {
    assert.equal(main(['audit', '--opencode', '--fix'], { out: s => lines.push(s), err: s => lines.push(s) }), 0)
  } finally {
    Object.assign(process.env, env)
  }
  assert.match(lines.join('\n'), /re-audit \d+ -> 0 distinct values/)
  assert.deepEqual(shape(copy), before, 'a non-content column changed')
  const db = new DatabaseSync(copy)
  db.exec('pragma foreign_keys = ON')
  assert.equal(db.prepare('pragma foreign_key_check').all().length, 0)
  assert.equal(db.prepare('pragma integrity_check').get().integrity_check, 'ok')
  for (const { data } of db.prepare('select data from message union all select data from part').all() as any[]) assert.ok(!data.includes(KEY) && !data.includes(PW))
  db.close()
  assert.equal(new DatabaseSync(orig).prepare('select data from message').get().data.includes(KEY), true) // the original is untouched
})

test('fixStore: replacing a value that lifts a line-level allow on a neighbour still ends at 0 (a real store: +325 matches)', () => {
  const { db } = realStore()
  db.prepare("update part set data = ? where id = 'prt1'").run(JSON.stringify({ text: 'pw=Hunter99x safe=abcdefgh;' }))
  // P is suppressed on a line that looks like "safe=<letters>;"; Q finds that letters value; replacing it lifts P's allow.
  const c = compile(merge({ patterns: [
    { name: 'Q', regex: 'safe=([a-z]{6,});', group: 1 },
    { name: 'P', regex: 'pw=(\\S{6,})', group: 1, allow: [{ target: 'line', regexes: [{ regex: 'safe=[a-z]+;' }] }] },
  ] } as any))
  const r = fixStore(db, c)
  assert.equal(r.after, 0)
  const data = db.prepare("select data from part where id = 'prt1'").get().data
  assert.ok(!data.includes('abcdefgh') && !data.includes('Hunter99x'), data)
  assert.equal(db.prepare('pragma foreign_key_check').all().length, 0)
})

test('live scrub is scoped to the session: its rows are scrubbed, another session is not touched', () => {
  const { db, SID } = realStore()
  db.prepare("insert into session (id, project_id, slug, directory, title, version, time_created, time_updated) values ('ses_other', 'prj', 'o', '/w', 'other', '1', 0, 0)").run()
  db.prepare("insert into message (id, session_id, time_created, time_updated, data) values ('msg2', 'ses_other', 0, 0, ?)").run(JSON.stringify({ text: `key ${KEY}` }))
  const n = scrubStore(db, new Map([[KEY, 'STRIPE_KEY']]), undefined, SID)
  assert.ok(n > 0)
  assert.ok(!db.prepare("select data from message where id = 'msg1'").get().data.includes(KEY))
  assert.ok(db.prepare("select data from message where id = 'msg2'").get().data.includes(KEY))
})

// opencode 2.x: a fake ctx that records the hooks setup() registers (payload shapes as measured on 2.0.22).
async function v2(directory: string) {
  const hooks: Record<string, (h: any) => unknown> = {}
  const reg = (dom: string) => ({ hook: async (name: string, cb: (h: any) => unknown) => ((hooks[`${dom} ${name}`] = cb), { dispose() {} }) })
  await setup({ location: { directory }, session: reg('session'), tool: reg('tool') })
  return hooks
}

test('dual export: one default export serves opencode 1.x (server) and 2.x (setup)', () => {
  assert.equal(veilpipe.id, 'veilpipe')
  assert.equal(veilpipe.server, VeilpipePlugin)
  assert.equal(veilpipe.setup, setup)
})

test('2.x: prompt, shell result and context are redacted; a slice is refused; the raw shell output file is scrubbed', async () => {
  const h = await v2(dir)
  assert.deepEqual(Object.keys(h).sort(), ['session context', 'session prompt', 'tool execute.after', 'tool execute.before'])
  const p = { sessionID: 's1', prompt: { text: `deploy with ${KEY}`, files: [] } }
  await h['session prompt']!(p)
  assert.match(p.prompt.text, /^deploy with \$STRIPE_KEY/) // the note only comes with a value first seen now
  assert.ok(!p.prompt.text.includes(KEY))
  // 2.x writes every shell command's raw output to <data>/opencode/shell/<project>/sh_<id>.out before execute.after.
  const out = join(dir, 'data', 'opencode', 'shell', 'proj1', 'sh_1.out')
  mkdirSync(join(dir, 'data', 'opencode', 'shell', 'proj1'), { recursive: true })
  writeFileSync(out, `DB_PASSWORD=${PW}\n`)
  const raw = `DB_PASSWORD=${PW}\n`
  const r = { tool: 'shell', sessionID: 's1', input: { command: 'cat secret.env' }, status: 'completed',
    result: { output: { exit: 0, truncated: false, output: raw, status: 'completed' }, content: [{ type: 'text', text: raw }], metadata: { exit: 0 } } }
  await h['tool execute.after']!(r)
  assert.ok(!JSON.stringify(r).includes(PW))
  assert.equal(r.result.output.exit, 0)
  assert.match(r.result.output.output, /DB_PASSWORD=\$DB_PASSWORD/)
  assert.equal(readFileSync(out, 'utf8'), 'DB_PASSWORD=$DB_PASSWORD**\n') // masked in place, same byte length
  await assert.rejects(async () => h['tool execute.before']!({ tool: 'shell', input: { command: 'echo ${STRIPE_KEY:0:8}' } }), /slices or transforms/)
  const c = { messages: [{ role: 'user', content: [{ type: 'text', text: `pw ${PW} key ${KEY}` }] }] }
  await h['session context']!(c)
  assert.ok(!JSON.stringify(c).includes(KEY) && !JSON.stringify(c).includes(PW))
})

test('2.x fail closed: broken patterns withhold the prompt, refuse tools, block the model call', async () => {
  const bad = join(dir, 'bad2'); mkdirSync(join(bad, '.veilpipe'), { recursive: true })
  writeFileSync(join(bad, '.veilpipe', 'patterns.json'), '{ broken')
  const h = await v2(bad)
  const p = { prompt: { text: `key ${KEY}` } }
  await h['session prompt']!(p)
  assert.match(p.prompt.text, /veilpipe is OFF/)
  await assert.rejects(async () => h['tool execute.before']!({ tool: 'shell', input: { command: 'ls' } }), /veilpipe is OFF/)
  await assert.rejects(async () => h['session context']!({ messages: [] }), /veilpipe is OFF/)
  const r = { result: { output: { exit: 0, output: `pw ${PW}` }, content: [{ type: 'text', text: `pw ${PW}` }] } }
  await h['tool execute.after']!(r)
  assert.ok(!JSON.stringify(r).includes(PW))
  load(dir) // later tests use the good patterns
})

test('veilpipe audit --opencode [--fix] covers 2.x shell output files and logs; clean files are left untouched', async () => {
  const { main } = await import('../cli/veilpipe.ts')
  const d = mkdtempSync(join(tmpdir(), 'vp-oc-files-'))
  const shellOut = join(d, 'data', 'opencode', 'shell', 'proj1', 'sh_1.out')
  const log = join(d, 'data', 'opencode', 'log', 'opencode.log')
  const clean = join(d, 'data', 'opencode', 'shell', 'proj1', 'sh_2.out')
  mkdirSync(join(d, 'data', 'opencode', 'shell', 'proj1'), { recursive: true })
  mkdirSync(join(d, 'data', 'opencode', 'log'), { recursive: true })
  writeFileSync(shellOut, `STRIPE_KEY=${KEY}\n`)
  writeFileSync(log, `level=INFO message="cli starting" args="[\\"run\\",\\"deploy with ${KEY}\\"]" role=cli\nlevel=INFO message=ok\n`)
  writeFileSync(clean, 'total 0\n')
  const env = { OPENCODE_DB: process.env.OPENCODE_DB, XDG_STATE_HOME: process.env.XDG_STATE_HOME, XDG_DATA_HOME: process.env.XDG_DATA_HOME }
  Object.assign(process.env, { OPENCODE_DB: join(d, 'none.db'), XDG_STATE_HOME: join(d, 'state'), XDG_DATA_HOME: join(d, 'data') })
  const lines: string[] = []
  const io = { out: (s: string) => lines.push(s), err: (s: string) => lines.push(s) }
  try {
    assert.equal(main(['audit', '--opencode'], io), 1)
    assert.match(lines.join('\n'), /found 1 file\(s\) in .*shell: 1 distinct values/)
    assert.match(lines.join('\n'), /found 1 file\(s\) in .*log: 1 distinct values/)
    assert.ok(readFileSync(shellOut, 'utf8').includes(KEY)) // audit alone never writes
    assert.ok(!lines.join('\n').includes(KEY)) // values are never printed
    assert.equal(main(['audit', '--opencode', '--fix'], io), 0)
    assert.equal(main(['audit', '--opencode'], io), 0)
  } finally {
    Object.assign(process.env, env)
  }
  assert.equal(readFileSync(shellOut, 'utf8'), 'STRIPE_KEY=$STRIPE_KEY\n')
  assert.ok(!readFileSync(log, 'utf8').includes(KEY) && readFileSync(log, 'utf8').endsWith('level=INFO message=ok\n'))
  assert.equal(readFileSync(clean, 'utf8'), 'total 0\n')
})

test('fixStore on the opencode 2.0.22 schema: session_v2 title, inbox and pending rows scrubbed; ids and credentials untouched', () => {
  const db = new DatabaseSync(':memory:')
  db.exec('pragma foreign_keys = ON')
  db.exec(readFileSync(new URL('./fixtures/opencode-2.0-schema.sql', import.meta.url), 'utf8'))
  const SID = 'ses_FAKEsk_test_DEMO0000FAKE0000FAKE00ID' // a secret-SHAPED id: must never be touched
  db.prepare("insert into project (id, worktree, time_created, time_updated, sandboxes) values ('prj', '/w', 0, 0, '[]')").run()
  // 2.x titles the session from the prompt: an unprotected session's title holds the raw key (measured 10-08).
  db.prepare("insert into session_v2 (id, project_id, slug, directory, title, version, time_created, time_updated) values (?, 'prj', 's', '/w', ?, '2', 0, 0)").run(SID, `key ${KEY}`)
  db.prepare("insert into session_message (id, session_id, type, seq, time_created, time_updated, data) values ('m1', ?, 'user', 1, 0, 0, ?)").run(SID, JSON.stringify({ text: `key ${KEY}` }))
  db.prepare("insert into session_inbox (id, session_id, type, payload, delivery, enqueued_seq, time_created) values ('i1', ?, 'prompt', ?, 'steer', 1, 0)").run(SID, JSON.stringify({ text: `pw DB_PASSWORD=${PW}` }))
  db.prepare("insert into session_pending (id, session_id, type, data, admitted_seq, time_created) values ('p1', ?, 'prompt', ?, 1, 0)").run(SID, JSON.stringify({ text: `key ${KEY}` }))
  db.prepare("insert into credential (id, label, value, time_created, time_updated) values ('cred', 'stripe', ?, 0, 0)").run(KEY)
  const c = compile(load(dir).file)
  const r = fixStore(db, c)
  assert.equal(r.after, 0)
  const dump = JSON.stringify(['session_v2', 'session_message', 'session_inbox', 'session_pending'].map(t => db.prepare(`select * from ${t}`).all()))
  assert.ok(!dump.replaceAll(SID, '').includes(KEY) && !dump.includes(PW), 'a raw value survived in a 2.x content table')
  assert.equal(db.prepare('select id from session_v2').get().id, SID)
  assert.equal(db.prepare('select value from credential').get().value, KEY) // opencode's own credential store: never changed
  assert.equal(db.prepare('pragma foreign_key_check').all().length, 0)
  assert.equal(findInStore(db, c).found.size, 0)
})

test('maskInPlace: a log another process keeps appending to is masked in place; no appended line is lost (macOS 10-08)', async () => {
  const { maskInPlace } = await import('../opencode/store.ts')
  const { spawn } = await import('node:child_process')
  const d = mkdtempSync(join(tmpdir(), 'vp-oc-log-'))
  const log = join(d, 'opencode.log')
  const argv = `level=INFO message="cli starting" args="[\\"run\\",\\"deploy with ${KEY}\\"]" role=cli\n`
  writeFileSync(log, argv)
  // opencode's service writes the log the whole time: 400 lines, one every millisecond, O_APPEND.
  const w = spawn(process.execPath, ['-e', `const fs=require('fs');let i=0;const t=setInterval(()=>{fs.appendFileSync(${JSON.stringify(log)},'line '+i+'\\n');if(++i===400)clearInterval(t)},1)`])
  let masked = 0
  await new Promise(r => setTimeout(r, 60))
  for (let i = 0; i < 5; i++) masked += maskInPlace(log, new Map([[KEY, 'STRIPE_KEY']]))
  await new Promise(r => w.on('exit', r))
  const text = readFileSync(log, 'utf8')
  assert.equal(masked, 1)
  assert.ok(!text.includes(KEY))
  assert.ok(text.startsWith(argv.replace(KEY, '$STRIPE_KEY' + '*'.repeat(KEY.length - '$STRIPE_KEY'.length))))
  for (let i = 0; i < 400; i++) assert.ok(text.includes(`line ${i}\n`), `appended line ${i} lost`)
  assert.equal(maskInPlace(log, new Map([[KEY, 'STRIPE_KEY']])), 0)
})

test('2.x: a log line flushed AFTER every scrub (the run CLI argv, macOS 10-08) is masked by the log watcher', async () => {
  const logDir = join(dir, 'data', 'opencode', 'log')
  mkdirSync(logDir, { recursive: true })
  const log = join(logDir, 'opencode.log')
  writeFileSync(log, 'level=INFO message="service started" role=server\n')
  const h = await v2(dir)
  await h['session prompt']!({ sessionID: 's2', prompt: { text: `deploy with ${KEY}` } }) // learns the key, starts the watcher
  const { appendFileSync } = await import('node:fs')
  appendFileSync(log, `level=INFO message="cli starting" args="[\\"run\\",\\"deploy with ${KEY}\\"]" role=cli\n`) // the late flush
  let text = ''
  for (let i = 0; i < 20 && (text = readFileSync(log, 'utf8')).includes(KEY); i++) await new Promise(r => setTimeout(r, 100))
  assert.ok(!text.includes(KEY), 'the late-flushed argv line stayed raw')
  assert.match(text, /deploy with \$STRIPE_KEY\*+/)
  assert.ok(text.startsWith('level=INFO message="service started" role=server\n'))
})

test('audit --opencode on a 2.x store: the dry run names table.column rows and files and writes nothing; --fix backs up first (private), then fixes', async () => {
  const { main } = await import('../cli/veilpipe.ts')
  const { statSync, readdirSync, chmodSync } = await import('node:fs')
  const d = mkdtempSync(join(tmpdir(), 'vp-oc-v2fix-'))
  const store = join(d, 'opencode.db')
  const mk = new DatabaseSync(store)
  mk.exec(readFileSync(new URL('./fixtures/opencode-2.0-schema.sql', import.meta.url), 'utf8'))
  mk.prepare("insert into project (id, worktree, time_created, time_updated, sandboxes) values ('prj', '/w', 0, 0, '[]')").run()
  mk.prepare("insert into session_v2 (id, project_id, slug, directory, title, version, time_created, time_updated) values ('s1', 'prj', 's', '/w', ?, '2', 0, 0)").run(`key ${KEY}`)
  mk.prepare("insert into session_message (id, session_id, type, seq, time_created, time_updated, data) values ('m1', 's1', 'user', 1, 0, 0, ?)").run(JSON.stringify({ text: `key ${KEY}` }))
  mk.prepare("insert into session_message (id, session_id, type, seq, time_created, time_updated, data) values ('m2', 's1', 'user', 2, 0, 0, ?)").run(JSON.stringify({ text: `pw DB_PASSWORD=${PW}` }))
  mk.prepare("insert into credential (id, label, value, time_created, time_updated) values ('cred', 'stripe', ?, 0, 0)").run(KEY)
  mk.close()
  const shellOut = join(d, 'data', 'opencode', 'shell', 'p', 'sh_1.out')
  mkdirSync(join(d, 'data', 'opencode', 'shell', 'p'), { recursive: true })
  writeFileSync(shellOut, `STRIPE_KEY=${KEY}\n`)
  const bytes = readFileSync(store)
  const env = { OPENCODE_DB: process.env.OPENCODE_DB, XDG_STATE_HOME: process.env.XDG_STATE_HOME, XDG_DATA_HOME: process.env.XDG_DATA_HOME }
  Object.assign(process.env, { OPENCODE_DB: store, XDG_STATE_HOME: join(d, 'state'), XDG_DATA_HOME: join(d, 'data') })
  const lines: string[] = []
  const io = { out: (s: string) => lines.push(s), err: (s: string) => lines.push(s) }
  try {
    for (const args of [['audit', '--opencode'], ['audit', '--opencode', '--dry-run']]) {
      lines.length = 0
      assert.equal(main(args, io), 1)
      const out = lines.join('\n')
      assert.match(out, /would rewrite session_v2\.title: 1 row/)
      assert.match(out, /would rewrite session_message\.data: 2 row/)
      assert.match(out, /would rewrite .*sh_1\.out/)
      assert.ok(!/credential/.test(out.replace(/login\/credential tables/, '')), 'credential must never be planned')
      assert.ok(!out.includes(KEY) && !out.includes(PW))
    }
    assert.deepEqual(readFileSync(store), bytes, 'the dry run wrote to the store')
    assert.equal(main(['audit', '--opencode', '--fix', '--dry-run'], io), 2)
    assert.deepEqual(readFileSync(store), bytes)
    // a backup that cannot be written stops --fix before any write
    chmodSync(d, 0o500)
    lines.length = 0
    try {
      assert.equal(main(['audit', '--opencode', '--fix'], io), 1)
    } finally {
      chmodSync(d, 0o700)
    }
    assert.match(lines.join('\n'), /backup failed, nothing was changed/)
    assert.deepEqual(readFileSync(store), bytes)
    assert.ok(readFileSync(shellOut, 'utf8').includes(KEY))
    lines.length = 0
    assert.equal(main(['audit', '--opencode', '--fix'], io), 0)
    assert.match(lines.join('\n'), /re-audit \d+ -> 0 distinct values/)
  } finally {
    Object.assign(process.env, env)
  }
  const bak = readdirSync(d).filter(f => f.startsWith('veilpipe-backup-'))
  assert.equal(bak.length, 1)
  const b = join(d, bak[0]!)
  assert.equal(statSync(b).mode & 0o777, 0o700)
  assert.equal(statSync(join(b, 'opencode.db')).mode & 0o777, 0o600)
  // the backup is the pre-fix store (raw values: it is the way back); the live store and shell file are fixed
  const old = new DatabaseSync(join(b, 'opencode.db'))
  assert.ok(old.prepare('select title from session_v2').get().title.includes(KEY))
  assert.equal(old.prepare('pragma integrity_check').get().integrity_check, 'ok')
  old.close()
  assert.ok(readFileSync(join(b, 'shell', 'p', 'sh_1.out'), 'utf8').includes(KEY))
  const now = new DatabaseSync(store)
  assert.ok(!now.prepare('select title from session_v2').get().title.includes(KEY))
  assert.equal(now.prepare('select value from credential').get().value, KEY)
  assert.equal(now.prepare('pragma foreign_key_check').all().length, 0)
  now.close()
  assert.equal(readFileSync(shellOut, 'utf8'), 'STRIPE_KEY=$STRIPE_KEY\n')
})

test('redactCell (audit --opencode --fix): numbers in a rewritten JSON cell come back exactly', () => {
  const c = compile(load(dir).file)
  const cell = `{"time":{"created":1791476018678},"big":12345678901234567890,"cost":0.10,"text":"key ${KEY}"}`
  assert.equal(redactCell(cell, c, new Map()), cell.replace(KEY, '$STRIPE_KEY'))
  assert.equal(redactCell('{"n":12345678901234567890,"text":"clean"}', c, new Map()), undefined) // no hit: untouched
})

test('bench/fix-number-impact.ts: counts what an old --fix rewrote, reformatted and changed in value; read-only', async () => {
  const { spawnSync } = await import('node:child_process')
  const d = mkdtempSync(join(tmpdir(), 'vp-oc-impact-'))
  const store = join(d, 'pre-fix.db')
  const mk = new DatabaseSync(store)
  mk.exec(readFileSync(new URL('./fixtures/opencode-2.0-schema.sql', import.meta.url), 'utf8'))
  mk.prepare("insert into project (id, worktree, time_created, time_updated, sandboxes) values ('prj', '/w', 0, 0, '[]')").run()
  mk.prepare("insert into session_v2 (id, project_id, slug, directory, title, version, time_created, time_updated) values ('s1', 'prj', 's', '/w', 't', '2', 0, 0)").run()
  const cells = [`{"n":12345678901234567890,"text":"key ${KEY}"}`, `{"cost":1.0,"text":"key ${KEY}"}`, `{"t":1791476018678,"text":"key ${KEY}"}`, '{"n":12345678901234567890,"text":"clean"}']
  cells.forEach((c, i) => mk.prepare("insert into session_message (id, session_id, type, seq, time_created, time_updated, data) values (?, 's1', 'user', ?, 0, 0, ?)").run(`m${i}`, i, c))
  mk.close()
  const bytes = readFileSync(store)
  const run = (db: string) => spawnSync(process.execPath, [new URL('../bench/fix-number-impact.ts', import.meta.url).pathname, db], { encoding: 'utf8', env: { ...process.env } })
  const r = run(store)
  assert.equal(r.status, 1)
  assert.match(r.stdout, /session_message\.data: 3 cell\(s\) rewritten by --fix · 2 reformatted · 1 with a changed number value/)
  assert.ok(!r.stdout.includes(KEY))
  assert.deepEqual(readFileSync(store), bytes, 'the check wrote to the store')
  const w = new DatabaseSync(store)
  w.prepare("delete from session_message where id = 'm0'").run()
  w.close()
  assert.equal(run(store).status, 0) // no integer over 2^53 left in a rewritten cell
})
