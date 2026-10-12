import { expect, mock, test } from 'claude-code/testing'

// A fixture patterns file (a hooks module cannot import JSON; test/core.node.ts covers the shipped one).
const PATTERNS = {
  patterns: [
    { name: 'STRIPE_KEY', regex: '\\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,}' },
    { name: 'GITHUB_TOKEN', regex: '\\bgh[pousr]_[A-Za-z0-9]{30,}' },
    { name: 'DB_PASSWORD', regex: '\\b(?:postgres(?:ql)?|mysql)://[^\\s:/@]+:([^\\s@/]{3,})@', group: 1 },
  ],
}

// FAKE values only.
const FAKE_STRIPE = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKE00'
const FAKE_DB = 'postgres://admin:FakePassw0rd123@db.example.com:5432/app'
const user = { kind: 'user' } as const

// The engine beneath the plugin: a home with no user patterns, and the fixture as the plugin's patterns.json.
// (Patterns load lazily on first use, so no session.start is needed.)
let on_: any
async function started(_$: any) {
  mock.env(on_, { HOME: '/nonexistent-home' })
  on_('session.cwd', () => ({ value: '/nonexistent-work' }))
  // Only the plugin's own patterns.json exists; no user or project file.
  on_('fs.exists', ($: any, e: any) => ({ value: e.path.endsWith('/patterns.json') && !e.path.startsWith('/nonexistent-') }))
  on_('fs.read', () => ({ value: JSON.stringify(PATTERNS) }))
}

test('a pasted key reaches the model as $NAME, with a note beside it', async ($, on) => {
  on_ = on
  let seen = ''
  let ctx: readonly string[] = []
  on('prompt.submit', ($, e) => ((seen = e.text), (ctx = e.context ?? []), { text: e.text }))
  await started($)
  await $.prompt.submit({ text: `use this key ${FAKE_STRIPE} for stripe`, wait: false, origin: user } as any)
  expect(seen).toBe('use this key $STRIPE_KEY for stripe')
  expect(ctx.join(' ')).toContain('$STRIPE_KEY')
})

test('a connection string keeps its shape and loses its password', async ($, on) => {
  on_ = on
  let seen = ''
  on('prompt.submit', ($, e) => ((seen = e.text), { text: e.text }))
  await started($)
  await $.prompt.submit({ text: `db is ${FAKE_DB}`, wait: false, origin: user } as any)
  expect(seen).toBe('db is postgres://admin:$DB_PASSWORD@db.example.com:5432/app')
})

test('ordinary prompts pass untouched', async ($, on) => {
  on_ = on
  const texts = ['run npm test and fix the failing snapshot', 'read the key from process.env.STRIPE_KEY', 'commit 3f9a2b7c1d8e4f6a0b5c9d2e7f1a3b8c4d6e0f2a']
  const seen: string[] = []
  on('prompt.submit', ($, e) => (seen.push(e.text), { text: e.text }))
  await started($)
  for (const text of texts) await $.prompt.submit({ text, wait: false, origin: user } as any)
  expect(seen).toEqual(texts)
})

test('tool output holding a key is redacted before the model reads it', async ($, on) => {
  on_ = on
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: `GITHUB=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000\nok`, stderr: '', interrupted: false } }) as any)
  await started($)
  const ran: any = await $.tool.call({ tool: 'Bash', command: 'cat .env.example' } as any)
  expect(ran.result.stdout).toBe('GITHUB=$GITHUB_TOKEN\nok')
})

test('a fragment of a replaced value in tool output is hidden too', async ($, on) => {
  on_ = on
  on('prompt.submit', ($, e) => ({ text: e.text }))
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: `prefix ${FAKE_STRIPE.slice(0, 14)}`, stderr: '', interrupted: false } }) as any)
  await started($)
  await $.prompt.submit({ text: `key ${FAKE_STRIPE}`, wait: false, origin: user } as any)
  const ran: any = await $.tool.call({ tool: 'Bash', command: 'echo hi' } as any)
  expect(ran.result.stdout.includes(FAKE_STRIPE.slice(0, 14))).toBe(false)
})

test('a Bash command that slices a protected variable is denied', async ($, on) => {
  on_ = on
  let ran = false
  on('prompt.submit', ($, e) => ({ text: e.text }))
  on('tool.call', { tool: 'Bash' }, () => ((ran = true), { result: { stdout: 'sk_', stderr: '', interrupted: false } }) as any)
  await started($)
  await $.prompt.submit({ text: `key ${FAKE_STRIPE}`, wait: false, origin: user } as any)
  const r: any = await $.tool.call({ tool: 'Bash', command: 'echo ${STRIPE_KEY:0:3}' } as any)
  expect(ran).toBe(false)
  expect(JSON.stringify(r)).toContain('slices')
})

test('a message that only quotes a Keychain read runs; the read itself is denied (10-12, v0.2.5 on the Mac)', async ($, on) => {
  on_ = on
  const ran: string[] = []
  on('tool.call', { tool: 'Bash' }, ($, e: any) => (ran.push(e.command), { result: { stdout: 'sent', stderr: '', interrupted: false } }) as any)
  await started($)
  const K = 'security find-generic-password -s veilpipe-store'
  const msg: any = await $.tool.call({ tool: 'Bash', command: `chat reply r-1 "$(cat <<'EOF'\nI can't run ${K} here.\nEOF\n)"` } as any)
  expect(JSON.stringify(msg)).toContain('sent')
  const read: any = await $.tool.call({ tool: 'Bash', command: `${K} -w` } as any)
  expect(JSON.stringify(read)).toContain('reads the Keychain')
  expect(ran.length).toBe(1)
})

test('a broken patterns file refuses prompts instead of passing them raw (fail closed)', async ($, on) => {
  let reached = false
  mock.env(on, { HOME: '/nonexistent-home' })
  on('session.cwd', () => ({ value: '/nonexistent-work' }))
  on('fs.exists', ($: any, e: any) => ({ value: !e.path.startsWith('/nonexistent-') }))
  on('fs.read', () => ({ value: JSON.stringify({ patterns: [{ name: 'BAD', regex: '(' }] }) }))
  on('prompt.submit', ($, e) => ((reached = true), { text: e.text }))
  const r: any = await $.prompt.submit({ text: `key ${FAKE_STRIPE}`, wait: false, origin: user } as any)
  expect(reached).toBe(false)
  expect(JSON.stringify(r)).toContain('veilpipe is OFF')
})

test('a Write that puts the text $STRIPE_KEY into code is denied with guidance; a shell file is fine', async ($, on) => {
  on_ = on
  const written: string[] = []
  on('prompt.submit', ($, e) => ({ text: e.text }))
  on('tool.call', { tool: 'Write' }, ($, e: any) => (written.push(e.file_path), { result: { type: 'create', filePath: e.file_path } }) as any)
  await started($)
  await $.prompt.submit({ text: `my key ${FAKE_STRIPE}`, wait: false, origin: user } as any)
  const bad: any = await $.tool.call({ tool: 'Write', file_path: '/w/config.js', content: "module.exports = { key: process.env.STRIPE_KEY || '$STRIPE_KEY' }" } as any)
  expect(JSON.stringify(bad)).toContain('process.env.STRIPE_KEY')
  const ok: any = await $.tool.call({ tool: 'Write', file_path: '/w/run.sh', content: 'curl -u "$STRIPE_KEY:" https://api.example.com' } as any)
  expect(written).toEqual(['/w/run.sh'])
  expect(JSON.stringify(ok)).toContain('run.sh')
})

// v0.2.1 bug: `head README.md` auto-saved the README's example keys. Tool output is saved only from the
// user's environment (env dump, .env file) and never when the value says it is fake; a pasted key still is.
test('auto-save: a README read stores nothing; a .env read and a paste do', async ($, on) => {
  on_ = on
  const saves: string[] = []
  on('process.run', ($: any, e: any) => {
    if (e.argv.includes('_load')) return { value: { exitCode: 0, stdout: JSON.stringify({ scope: '/w', entries: [] }), stderr: '' } }
    if (e.argv.includes('_save')) return (saves.push(e.argv[e.argv.length - 1]), { value: { exitCode: 0, stdout: 'saved', stderr: '' } })
    return { value: { exitCode: 0, stdout: '', stderr: '' } }
  })
  // Fake to a reader, but with none of the markers looksFake skips, so only the source rule can stop it.
  const REAL_LOOKING = 'sk_test_NOTREALNOTREALNOTREALNOTREAL1'
  let out = ''
  const toasts: string[] = []
  on('ui.toast', ($: any, e: any) => { toasts.push(String(e.message ?? e.text ?? JSON.stringify(e))); return { value: undefined } })
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: out, stderr: '', interrupted: false } }) as any)
  on('prompt.submit', ($, e) => ({ text: e.text }))
  await started($)
  out = `Set STRIPE_KEY=${FAKE_STRIPE} or STRIPE_KEY=${REAL_LOOKING}`
  const readme = JSON.stringify(await $.tool.call({ tool: 'Bash', command: 'head README.md' } as any))
  expect(saves).toEqual([])
  // v0.2.3: values that will not be saved stay off the free base name, so the project's real key can take it.
  expect(readme).toContain('$STRIPE_KEY_2')
  expect(readme).not.toMatch(/\$STRIPE_KEY(?![_0-9])/)
  out = `STRIPE=${FAKE_STRIPE}`
  await $.tool.call({ tool: 'Bash', command: 'cat .env' } as any)
  expect(saves).toEqual([]) // a .env value that says FAKE is not saved either
  expect(toasts.filter(t => t.includes('looks like a placeholder'))).toHaveLength(1)
  out = `STRIPE=${REAL_LOOKING.replace(/1$/, '2')}`
  await $.tool.call({ tool: 'Bash', command: 'cat .env.local' } as any)
  expect(saves).toEqual(['STRIPE_KEY'])
  // A value first seen in the README keeps the name the model already knows it by.
  out = `STRIPE_OLD=${REAL_LOOKING}`
  await $.tool.call({ tool: 'Bash', command: 'cat .env' } as any)
  expect(saves).toEqual(['STRIPE_KEY', 'STRIPE_KEY_3'])
  await $.prompt.submit({ text: `db is ${FAKE_DB}`, wait: false, origin: user } as any)
  expect(saves).toEqual(['STRIPE_KEY', 'STRIPE_KEY_3', 'DB_PASSWORD'])
})
