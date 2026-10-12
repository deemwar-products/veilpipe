// node --test test/core.node.ts  (Node >= 22.18; not *.test.ts, which claude plugin test owns). FAKE values only.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, existsSync, lstatSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHash } from 'node:crypto'
const createHashHex = (v: string) => createHash('sha256').update(v).digest('hex')

import { compile, envSource, expandModifiers, looksFake, maskBlobs, merge, note, placeholderGuard, redact, referencedNames, runTests, scan, scrubFile, scrubFragments, scrubJsonl, sliceGuard, storeReadGuard, storeWants } from '../hooks/core.ts'
import { audit, doctor, fingerprint, main, mask, opencodeShim, opencodeTarget, scrubLargeFile, vaultFingerprints } from '../cli/veilpipe.ts'

const DEFAULTS = JSON.parse(readFileSync(new URL('../patterns.json', import.meta.url), 'utf8'))
const C = compile(DEFAULTS)
const GITLEAKS = JSON.parse(readFileSync(new URL('../rules/gitleaks.json', import.meta.url), 'utf8'))
const ALL = compile(merge(DEFAULTS, GITLEAKS))
const FAKE_STRIPE = 'sk_live_FAKEFAKEFAKEFAKEFAKEFAKE00'

function run(argv: string[], env: Record<string, string> = {}) {
  const out: string[] = []
  const err: string[] = []
  const saved = { ...process.env }
  Object.assign(process.env, env)
  try {
    const code = main(argv, { out: s => out.push(s), err: s => err.push(s) })
    return { code, out: out.join('\n'), err: err.join('\n') }
  } finally {
    process.env = saved
  }
}

test('shipped patterns pass their own suite', () => {
  const failed = runTests(DEFAULTS).filter(t => !t.ok)
  assert.deepEqual(failed, [])
})

test('the same value keeps one name; a second value gets _2', () => {
  const known = new Map<string, string>()
  const a = redact(`a ${FAKE_STRIPE}`, C, known)
  const b = redact(`b ${FAKE_STRIPE} c sk_test_FAKEFAKEFAKEFAKEFAKEFAKE11`, C, known)
  assert.equal(a.text, 'a $STRIPE_KEY')
  assert.equal(b.text, 'b $STRIPE_KEY c $STRIPE_KEY_2')
  assert.deepEqual(b.fresh.map(f => f.name), ['STRIPE_KEY_2'])
})

test('a value seen earlier is replaced even where no pattern fires', () => {
  const known = new Map<string, string>()
  redact('password: FakePass0000', C, known)
  assert.equal(redact('it was FakePass0000 all along', C, known).text, 'it was $PASSWORD all along')
})

test('references are left alone', () => {
  for (const s of ['API_KEY=$API_KEY', 'token: ${GITHUB_TOKEN}', 'PASSWORD={{DB_PASSWORD}}', 'STRIPE_KEY=YOUR_KEY_HERE'])
    assert.equal(redact(s, C).text, s)
})

test('fragments and encodings of a known value are scrubbed', () => {
  const known = new Map([[FAKE_STRIPE, 'STRIPE_KEY']])
  assert.equal(scrubFragments(`got ${FAKE_STRIPE.slice(0, 12)}!`, known), 'got $STRIPE_KEY!')
  assert.equal(scrubFragments(`b64 ${btoa(FAKE_STRIPE)}`, known), 'b64 $STRIPE_KEY')
  assert.equal(scrubFragments('got sk_!', known), 'got sk_!') // under 8 chars: the slice guard's job
})

test('slice guard', () => {
  const names = ['STRIPE_KEY']
  assert.match(sliceGuard('echo ${STRIPE_KEY:0:3}', names) ?? '', /slices/)
  assert.match(sliceGuard('echo "$STRIPE_KEY" | rev', names) ?? '', /pipes/)
  assert.match(sliceGuard('base64 <<< "$STRIPE_KEY"', names) ?? '', /encodes/)
  assert.equal(sliceGuard('echo "len=${#STRIPE_KEY}"', names), undefined)
  assert.equal(sliceGuard('curl -u "$STRIPE_KEY:" https://api.example.com', names), undefined)
})

test('transcript scrub catches raw and JSON-escaped forms', () => {
  const known = new Map([['Fake"Pass\\0000', 'PASSWORD']])
  const row = JSON.stringify({ type: 'queue-operation', content: 'pw Fake"Pass\\0000' })
  assert.equal(scrubJsonl(row, known), JSON.stringify({ type: 'queue-operation', content: 'pw $PASSWORD' }))
})

test('a bad pattern fails compile with its name', () => {
  assert.throws(() => compile({ patterns: [{ name: 'BAD', regex: '(' }] }), /BAD: bad regex/)
  assert.throws(() => compile({ patterns: [{ name: 'EMPTY', regex: 'x*' }] }), /empty string/)
  assert.throws(() => compile({ patterns: [{ name: 'lower', regex: 'x' }] }), /UPPER_SNAKE/)
})

test('merge: later files win; disabled switches off', () => {
  const m = merge(DEFAULTS, { patterns: [{ name: 'EMAIL', regex: '.', disabled: true }] })
  assert.equal(redact('mail jane@acme-corp.dev', compile(m)).text, 'mail jane@acme-corp.dev')
})

test('mask never shows the value', () => {
  assert.equal(mask(FAKE_STRIPE), '34 chars')
  assert.equal(mask('abc'), '3 chars')
})

test('cli: scan rewrites and lists masked values; --check exits 1', () => {
  const r = run(['scan', '--check', `key ${FAKE_STRIPE}`])
  assert.equal(r.code, 1)
  assert.equal(r.out, 'key $STRIPE_KEY')
  assert.match(r.err, /\$STRIPE_KEY {2}← {2}34 chars/)
  assert.ok(!r.err.includes('sk_')) // no part of the value, not even its prefix
  assert.ok(!r.err.includes(FAKE_STRIPE))
})

test('cli: scan text that starts with dashes (a pasted PEM block) is scanned, not taken as a flag', () => {
  // PEM fixtures live in ONE file (test/fixtures/pem.txt), so a repository secret scanner needs only one exclude.
  const pem = readFileSync(new URL('./fixtures/pem.txt', import.meta.url), 'utf8')
  const r = run(['scan', '--check', pem])
  assert.equal(r.code, 1)
  assert.equal(r.out, '$PRIVATE_KEY')
  assert.ok(!r.err.includes('nothing to replace'))
})

test('cli: add, list, rm, test against a scratch home', () => {
  const home = mkdtempSync(join(tmpdir(), 'veilpipe-'))
  const env = { VEILPIPE_HOME: home }
  assert.equal(run(['add', 'ACME_KEY', 'acme_[a-z0-9]{12}', '--hit', 'acme_fake00000000', '--miss', 'acme_x'], env).code, 0)
  assert.equal(run(['scan', 'x acme_fake00000000'], env).out, 'x $ACME_KEY')
  // An example that does not match is refused and nothing is written.
  const refused = run(['add', 'NOPE', 'nope_[0-9]+', '--hit', 'nothing', '--miss', 'nope_1'], env)
  assert.equal(refused.code, 1)
  assert.match(refused.err, /NOPE not added; it fails its own examples:\n  FAIL should match "nothing"\n  FAIL should not match "nope_1" \(matched "nope_1"\)/)
  assert.match(run(['list'], env).out, /\+ \$ACME_KEY/)
  assert.equal(run(['rm', 'EMAIL'], env).code, 0)
  assert.equal(run(['scan', 'jane@acme-corp.dev'], env).out, 'jane@acme-corp.dev')
  assert.equal(run(['test'], env).code, 0)
})

test('cli: install links the plugin into a skills folder, uninstall removes it', () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'veilpipe-')), 'skills', 'veilpipe')
  assert.equal(run(['install', '--dir', dir]).code, 0)
  assert.ok(lstatSync(dir).isSymbolicLink())
  assert.equal(run(['install', '--dir', dir]).code, 0) // idempotent
  assert.equal(run(['uninstall', '--dir', dir]).code, 0)
  assert.ok(!existsSync(dir))
})

test('vendored gitleaks: 217 text rules, all compile, namespaced, source pinned', () => {
  assert.equal(GITLEAKS.patterns.length, 217) // 222 minus the path-only and 4 file-type-scoped rules
  assert.equal(GITLEAKS.source.license, 'MIT')
  assert.match(GITLEAKS.source.commit, /^[0-9a-f]{12}$/)
  assert.ok(GITLEAKS.patterns.every((p: any) => p.name.startsWith('GL_') && /^[A-Z_][A-Z0-9_]*$/.test(p.as)))
  assert.equal(ALL.length, DEFAULTS.patterns.length + 217)
})

test('vendored rules never replace ours, and our suite still passes with them loaded', () => {
  assert.deepEqual(runTests(merge(DEFAULTS, GITLEAKS)).filter(t => !t.ok), [])
})

test('vendored rules catch formats ours do not, under their own names', () => {
  // Mixed-case fakes: gitleaks rules need entropy, so FAKEFAKE-style keys are below their floor.
  const cases: [string, RegExp][] = [
    ['glpat-FAKEFak3Xk9Qw2Lm7Zp4', /\$GITLAB_PAT\b/],
    ['npm_FAKEFak3Xk9Qw2Lm7Zp4Rt8VbN6cJ1hY5dS0', /\$NPM_ACCESS_TOKEN\b/],
    ['hf_FakeXkQwLmZpRtVbNcJhYdSeTuWaQzFake', /\$HUGGINGFACE_ACCESS_TOKEN\b/],
  ]
  for (const [fake, want] of cases) {
    assert.equal(scan(`token: ${fake}`, C).length, 0, `ours alone should miss ${fake}`)
    assert.match(redact(`token: ${fake}`, ALL).text, want)
  }
})

test('keywords, entropy and allowlists gate a pattern', () => {
  const p = { name: 'TOK', regex: 'tok_([A-Za-z0-9]{8,})', group: 1, keywords: ['tok_'], entropy: 3 }
  const c = compile({ patterns: [p] })
  assert.equal(scan('x tok_Ab3dE9gH2k', c).length, 1)
  assert.equal(scan('x tok_aaaaaaaaaa', c).length, 0) // entropy too low
  const allowed = compile({ patterns: [p], allow: { stopwords: ['e9g'] } })
  assert.equal(scan('x tok_Ab3dE9gH2k', allowed).length, 0) // stopword in the value
  const line = compile({ patterns: [{ ...p, allow: [{ regexes: [{ regex: '^# example' }], target: 'line' }] }] })
  assert.equal(scan('# example tok_Ab3dE9gH2k', line).length, 0)
  assert.equal(scan('real tok_Ab3dE9gH2k', line).length, 1)
})

test('group "first" takes the first capture that matched', () => {
  const c = compile({ patterns: [{ name: 'ALT', regex: 'a=(\\w{6,})|b=(\\w{6,})', group: 'first' }] })
  assert.equal(scan('b=Zq8Xk2Lm', c)[0]?.value, 'Zq8Xk2Lm')
})

test('no catastrophic backtracking: 235 patterns over hostile input stay fast', () => {
  for (const evil of ['a'.repeat(50_000), ('key=' + 'A1'.repeat(30) + ' ').repeat(2_000), ('x'.repeat(40) + '.').repeat(2_000)]) {
    const t0 = performance.now()
    scan(evil, ALL)
    assert.ok(performance.now() - t0 < 1_000, `took ${performance.now() - t0} ms on ${evil.slice(0, 8)}…`)
  }
})

// doctor with a stubbed `claude`, so no money is spent.
function stub(answers: { version?: string; list?: string; reply?: string; opencode?: string }) {
  return (argv: string[]) => {
    if (argv[0] === 'opencode') return answers.opencode ? { status: 0, stdout: answers.opencode } : { status: null, stdout: '' }
    if (argv[1] === '--version') return answers.version ? { status: 0, stdout: `${answers.version} (Claude Code)` } : { status: null, stdout: '' }
    if (argv[1] === 'plugin') return { status: 0, stdout: answers.list ?? '' }
    return { status: 0, stdout: answers.reply ?? '' }
  }
}
const level = (checks: { name: string; level: string }[], name: string) => checks.find(c => c.name === name)?.level

test('doctor: healthy, old or missing claude, disabled hooks', () => {
  const config = mkdtempSync(join(tmpdir(), 'veilpipe-cfg-'))
  const env = { HOME: config, CLAUDE_CONFIG_DIR: config, VEILPIPE_HOME: join(config, 'cm') }
  const ok = doctor({ run: stub({ version: '2.1.288', list: '❯ veilpipe@deemwar\n  Status: ✔ enabled' }), env })
  assert.deepEqual(ok.filter(c => c.level !== 'ok'), [])
  assert.equal(level(doctor({ run: stub({ version: '2.1.200' }), env }), 'claude'), 'fail')
  assert.equal(level(doctor({ run: stub({}), env }), 'claude'), 'fail')
  assert.equal(level(doctor({ run: stub({ version: '2.1.288' }), env }), 'installed'), 'warn')
  writeFileSync(join(config, 'settings.json'), JSON.stringify({ disableAllHooks: true }))
  assert.equal(level(doctor({ run: stub({ version: '2.1.288' }), env }), 'settings'), 'fail')
})

test('doctor: opencode is checked only when present, and warns until the plugin is installed', () => {
  const env = { HOME: mkdtempSync(join(tmpdir(), 'veilpipe-')), XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'veilpipe-')), VEILPIPE_HOME: mkdtempSync(join(tmpdir(), 'veilpipe-')) }
  assert.equal(level(doctor({ run: stub({ version: '2.1.288' }), env }), 'opencode'), undefined)
  assert.equal(level(doctor({ run: stub({ version: '2.1.288', opencode: '1.18.30' }), env }), 'opencode'), 'warn')
  assert.equal(level(doctor({ run: stub({ version: '2.1.288', opencode: '1.18.30' }), env, cwd: env.HOME }), 'opencode plugins'), undefined)
  mkdirSync(join(env.XDG_CONFIG_HOME, 'opencode', 'plugins'), { recursive: true })
  writeFileSync(join(env.XDG_CONFIG_HOME, 'opencode', 'plugins', 'audit-log.ts'), 'export const A = async () => ({})')
  assert.equal(level(doctor({ run: stub({ version: '2.1.288', opencode: '1.18.30' }), env, cwd: env.HOME }), 'opencode plugins'), 'warn')
  assert.equal(level(doctor({ run: stub({ version: '2.1.288', opencode: '1.18.30' }), env: { ...env, OPENCODE_PURE: '1' }, cwd: env.HOME }), 'opencode pure'), 'fail')
  // 2.x: not installed warns; the current shim is ok; a shim from before 2.x support FAILS (it loads nothing there).
  const v2 = () => level(doctor({ run: stub({ version: '2.1.288', opencode: 'opencode v2.0.22' }), env, cwd: env.HOME }), 'opencode')
  const v1 = () => level(doctor({ run: stub({ version: '2.1.288', opencode: '1.18.30' }), env, cwd: env.HOME }), 'opencode')
  const plugins = (oc: string) => level(doctor({ run: stub({ version: '2.1.288', opencode: oc }), env, cwd: env.HOME }), 'opencode plugins')
  const dir = join(env.XDG_CONFIG_HOME, 'opencode', 'plugins')
  rmSync(join(dir, 'audit-log.ts'))
  assert.equal(v2(), 'warn')
  const shim = opencodeTarget(env)
  assert.equal(shim, join(dir, '00-veilpipe.ts'))
  writeFileSync(shim, opencodeShim())
  assert.equal(v2(), 'ok')
  assert.equal(v1(), 'ok')
  // 2.x runs plugin hooks in file-name order: only a plugin sorting before ours is named; on 1.x every other plugin is.
  writeFileSync(join(dir, 'ctxguard.js'), 'export default {}')
  assert.equal(plugins('opencode v2.0.23'), undefined)
  assert.equal(plugins('1.18.30'), 'warn')
  writeFileSync(join(dir, '0-early.js'), 'export default {}')
  assert.equal(plugins('opencode v2.0.23'), 'warn')
  rmSync(join(dir, 'ctxguard.js')); rmSync(join(dir, '0-early.js'))
  // The old name (before 10-08): current content still loads but later than other plugins (warn); 1.x-only content
  // loads nothing on 2.x (FAIL).
  rmSync(shim)
  writeFileSync(join(dir, 'veilpipe.ts'), opencodeShim())
  assert.equal(v2(), 'warn')
  writeFileSync(join(dir, 'ctxguard.js'), 'export default {}')
  assert.equal(plugins('opencode v2.0.23'), 'warn') // 'ctxguard.js' sorts before 'veilpipe.ts'
  rmSync(join(dir, 'ctxguard.js'))
  writeFileSync(join(dir, 'veilpipe.ts'), opencodeShim().replace('export { default }', 'export { VeilpipePlugin }'))
  assert.equal(v2(), 'fail')
  assert.equal(v1(), 'warn')
  // install replaces our old-named shim (never two copies); uninstall removes what is ours.
  const saved = process.env.XDG_CONFIG_HOME
  process.env.XDG_CONFIG_HOME = env.XDG_CONFIG_HOME
  try {
    const io = { out: () => {}, err: () => {} }
    assert.equal(main(['install', '--opencode'], io), 0)
    assert.deepEqual(readdirSync(dir).sort(), ['00-veilpipe.ts'])
    assert.equal(v2(), 'ok')
    writeFileSync(join(dir, 'veilpipe.ts'), 'export default {} // someone else\'s')
    assert.equal(main(['uninstall', '--opencode'], io), 0)
    assert.deepEqual(readdirSync(dir), ['veilpipe.ts']) // a foreign file with the old name is left alone
  } finally {
    process.env.XDG_CONFIG_HOME = saved
  }
})

test('doctor: a leftover audit --opencode --fix backup (raw values) is flagged, even with opencode gone', () => {
  const config = mkdtempSync(join(tmpdir(), 'veilpipe-cfg-'))
  const data = join(config, 'data')
  const env = { HOME: config, CLAUDE_CONFIG_DIR: config, VEILPIPE_HOME: join(config, 'cm'), XDG_DATA_HOME: data }
  const healthy = { version: '2.1.288', list: '❯ veilpipe@deemwar\n  Status: ✔ enabled' }
  assert.equal(level(doctor({ run: stub(healthy), env }), 'opencode backups'), undefined)
  mkdirSync(join(data, 'opencode', 'veilpipe-backup-20261009-031500'), { recursive: true })
  const checks = doctor({ run: stub(healthy), env }) // no opencode on PATH
  assert.equal(level(checks, 'opencode backups'), 'warn')
  assert.match(checks.find(c => c.name === 'opencode backups')!.detail, /1 backup\(s\).*rm -r '.*veilpipe-backup-20261009-031500'/)
})

test('doctor --canary fails when the model sees the raw key', () => {
  const config = mkdtempSync(join(tmpdir(), 'veilpipe-cfg-'))
  const env = { HOME: config, CLAUDE_CONFIG_DIR: config, VEILPIPE_HOME: join(config, 'cm') }
  const leak = doctor({ canary: true, run: stub({ version: '2.1.288', reply: 'deploy with sk_live_FAKEFAKEFAKEFAKEFAKEFAKE00' }), env })
  assert.equal(level(leak, 'canary: model'), 'fail')
  const good = doctor({ canary: true, run: stub({ version: '2.1.288', reply: '`deploy with $STRIPE_KEY`' }), env })
  assert.equal(level(good, 'canary: model'), 'ok')
  // printed as '<name> <detail>': 'canary: model saw only $STRIPE_KEY, ...', not 'canary: model the model saw ...'
  assert.equal(good.find(c => c.name === 'canary: model')!.detail, 'saw only $STRIPE_KEY, never the fake key')
  assert.equal(leak.find(c => c.name === 'canary: model')!.detail, 'saw the raw fake key')
  assert.equal(level(good, 'canary: disk'), 'warn') // the stub writes no transcript
})

test('keyword index: overlapping and nested keywords all count as present', () => {
  // Each regex matches its own text; only the keyword gate decides whether the rule runs.
  const c = compile({
    patterns: [
      { name: 'LONG', regex: 'sk_live_[a-z]{6}', keywords: ['sk_live'] },
      { name: 'PREFIX', regex: 'zzz[0-9]{3}', keywords: ['sk_'] }, // only appears as the start of "sk_live"
      { name: 'INSIDE', regex: 'qqq[0-9]{3}', keywords: ['ve_a'] }, // starts inside "sk_live_abcdef"
    ],
  })
  assert.deepEqual(scan('sk_live_abcdef zzz123 qqq456', c).map(h => h.name), ['LONG', 'PREFIX', 'INSIDE'])
  assert.deepEqual(scan('zzz123 qqq456', c), []) // no keyword present: no rule runs
})

test('recall: every line of bench/recall-names.json (170 fake secret assignments) is caught by our patterns alone', () => {
  const lines: string[] = JSON.parse(readFileSync(new URL('../bench/recall-names.json', import.meta.url), 'utf8')).lines
  const missed = lines.filter(l => !scan(l, C).some(h => h.value.startsWith('Fake')))
  assert.deepEqual(missed, [])
})

// A fake file system whose `onRead` hook can append like another session would.
function fakeFs(initial: string, onRead?: (n: number, f: { text: string }) => void) {
  const f = { text: initial, reads: 0, writes: 0 }
  return {
    f,
    ops: {
      size: async () => f.text.length,
      read: async () => (onRead?.(++f.reads, f), f.text),
      write: async (_p: string, t: string) => void ((f.writes += 1), (f.text = t)),
    },
  }
}
const KNOWN = new Map([['sk_live_FAKEHISTORYSCRUBFAKEFAKE42', 'STRIPE_KEY']])
const ROW = (s: string) => JSON.stringify({ display: s }) + '\n'

test('scrubFile: replaces a known value in history.jsonl', async () => {
  const { f, ops } = fakeFs(ROW('other') + ROW('deploy with sk_live_FAKEHISTORYSCRUBFAKEFAKE42 now'))
  assert.equal(await scrubFile(ops, 'h', KNOWN), 'scrubbed')
  assert.equal(f.text, ROW('other') + ROW('deploy with $STRIPE_KEY now'))
  assert.equal(await scrubFile(ops, 'h', KNOWN), 'clean')
})

test('scrubFile: an append by another session between the two reads is never lost', async () => {
  // Read 2 sees a line another session appended after read 1: that pass must not write;
  // the retry starts from the new content and keeps the appended line.
  const { f, ops } = fakeFs(ROW('deploy with sk_live_FAKEHISTORYSCRUBFAKEFAKE42 now'), (n, file) => {
    if (n === 2) file.text += ROW('appended by another session')
  })
  assert.equal(await scrubFile(ops, 'h', KNOWN), 'scrubbed')
  assert.equal(f.text, ROW('deploy with $STRIPE_KEY now') + ROW('appended by another session'))
  assert.equal(f.writes, 1)
})

test('scrubFile: a file that keeps changing is left alone, not forced', async () => {
  const { f, ops } = fakeFs(ROW('sk_live_FAKEHISTORYSCRUBFAKEFAKE42'), (n, file) => {
    if (n % 2 === 0) file.text += ROW(`append ${n}`)
  })
  assert.equal(await scrubFile(ops, 'h', KNOWN), 'busy')
  assert.equal(f.writes, 0)
})

test('scrubFile: over the size limit it reports instead of reading', async () => {
  const { f, ops } = fakeFs(ROW('sk_live_FAKEHISTORYSCRUBFAKEFAKE42'))
  assert.equal(await scrubFile(ops, 'h', KNOWN, 10), 'too-large')
  assert.equal(f.reads, 0)
})

// A config dir with transcripts written "before install". FAKE values only.
function fixtureConfig() {
  const config = mkdtempSync(join(tmpdir(), 'veilpipe-audit-'))
  const proj = join(config, 'projects', '-work-app')
  mkdirSync(proj, { recursive: true })
  const clean = JSON.stringify({ type: 'user', message: { content: 'run npm test' } })
  const leaky = JSON.stringify({ type: 'user', message: { content: `key "${FAKE_STRIPE}"\tand\\path postgres://admin:FakePassw0rd123@db.example.com/app` } })
  const tool = JSON.stringify({ type: 'user', message: { content: [{ type: 'tool_result', content: 'GITHUB=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000' }] } })
  writeFileSync(join(proj, 'old.jsonl'), [clean, leaky, 'not json at all ' + FAKE_STRIPE, tool, ''].join('\n'))
  writeFileSync(join(proj, 'tidy.jsonl'), clean + '\n')
  writeFileSync(join(config, 'history.jsonl'), JSON.stringify({ display: `deploy with ${FAKE_STRIPE}` }) + '\n')
  const old = Date.now() / 1000 - 3600
  for (const f of [join(proj, 'old.jsonl'), join(proj, 'tidy.jsonl'), join(config, 'history.jsonl')]) utimesSync(f, old, old)
  return { config, proj, clean }
}

test('audit: finds secrets in old transcripts and history; reports names and counts, never values', () => {
  const { config } = fixtureConfig()
  const r = audit({ config })
  assert.deepEqual(r.map(x => x.path.replace(config, '')).sort(), ['/history.jsonl', '/projects/-work-app/old.jsonl'])
  const old = r.find(x => x.path.endsWith('old.jsonl'))!
  assert.deepEqual(old.hits, { STRIPE_KEY: 1, DB_PASSWORD: 1, GITHUB_TOKEN: 1 }) // the non-JSON line is not parsed
  assert.ok(!JSON.stringify(r).includes('FAKE'))
})

test('audit --fix: values become $NAME, every line still parses, untouched lines are byte-identical', () => {
  const { config, proj, clean } = fixtureConfig()
  const before = readFileSync(join(proj, 'old.jsonl'), 'utf8').split('\n')
  audit({ config, fix: true })
  const after = readFileSync(join(proj, 'old.jsonl'), 'utf8').split('\n')
  assert.equal(after.length, before.length)
  assert.equal(after[0], clean)
  assert.equal(after[2], before[2]) // not JSON: left exactly as it was
  for (const line of [after[1], after[3]]) assert.doesNotThrow(() => JSON.parse(line!))
  const row = JSON.parse(after[1]!)
  assert.equal(row.message.content, 'key "$STRIPE_KEY"\tand\\path postgres://admin:$DB_PASSWORD@db.example.com/app')
  assert.ok(!after.slice(0, 2).concat(after.slice(3)).join('\n').includes('FAKEFAKE'))
  assert.ok(!readFileSync(join(config, 'history.jsonl'), 'utf8').includes(FAKE_STRIPE))
  assert.deepEqual(audit({ config }), []) // a second audit finds nothing (the non-JSON line is never parsed)
})

test('audit --fix: numbers in a rewritten line come back exactly (no float rounding of big ids, 1.0 stays 1.0)', () => {
  const { config, proj } = fixtureConfig()
  const line = `{"type":"user","id":12345678901234567890,"f":1.0,"z":-0,"e":2e400,"message":{"content":"key ${FAKE_STRIPE}"}}`
  writeFileSync(join(proj, 'old.jsonl'), line + '\n')
  const old = Date.now() / 1000 - 3600
  utimesSync(join(proj, 'old.jsonl'), old, old)
  audit({ config, fix: true })
  assert.equal(readFileSync(join(proj, 'old.jsonl'), 'utf8'), line.replace(FAKE_STRIPE, '$STRIPE_KEY') + '\n')
})

test('audit --days N limits the audit to files written in the last N days; --recent warns that it is not a filter', () => {
  const { config, proj } = fixtureConfig() // old.jsonl and history.jsonl are an hour old
  const ancient = Date.now() / 1000 - 30 * 86400
  utimesSync(join(proj, 'old.jsonl'), ancient, ancient)
  assert.deepEqual(audit({ config, days: 7 }).map(r => r.path.replace(config, '')), ['/history.jsonl'])
  assert.equal(audit({ config }).length, 2) // without --days: every file
  const r = run(['audit', '--recent', '10080'], { CLAUDE_CONFIG_DIR: config })
  assert.match(r.err, /--recent 10080 only makes --fix skip files written in the last 10080 min.*--days N/)
})

test('audit --fix leaves a file written in the last minutes alone (a live session)', () => {
  const { config, proj } = fixtureConfig()
  const now = Date.now() / 1000
  utimesSync(join(proj, 'old.jsonl'), now, now)
  const r = audit({ config, fix: true })
  assert.match(r.find(x => x.path.endsWith('old.jsonl'))!.skipped ?? '', /last 10 min/)
  assert.ok(readFileSync(join(proj, 'old.jsonl'), 'utf8').includes(FAKE_STRIPE))
})

test('audit: a secret written as JSON inside a transcript string is still found (escaped quotes)', () => {
  const { config, proj } = fixtureConfig()
  writeFileSync(join(proj, 'nested.jsonl'), JSON.stringify({ type: 'user', message: { content: '{"password": "Fak3Nested0000"}' } }) + '\n')
  const old = Date.now() / 1000 - 3600
  utimesSync(join(proj, 'nested.jsonl'), old, old)
  assert.deepEqual(audit({ config }).find(x => x.path.endsWith('nested.jsonl'))?.hits, { PASSWORD: 1 })
})

test('a 3 MB embedded image does not stall the scan, and a key next to it is still found', () => {
  // Two 1.5M-char base64 runs, like screenshots in a transcript line (old code: about 2 s here, 15-26 s on a loaded machine).
  // Pseudo-random base64 (high LCG bits: the low bits repeat every 64 steps, and a repeating pattern does not reproduce the stall).
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let seed = 42
  const blob = 'iVBORw0KGgo' + Array.from({ length: 1_500_000 }, () => B64[Math.floor((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 65536) % 64]).join('')
  const text = `{"image":"${blob}","note":"key ${FAKE_STRIPE}","b":"${blob}"}`
  const t0 = performance.now()
  const hits = scan(text, ALL)
  assert.ok(performance.now() - t0 < 1_000, `took ${(performance.now() - t0).toFixed(0)} ms`)
  assert.deepEqual(hits.map(h => h.value), [FAKE_STRIPE])
  assert.equal(maskBlobs(text).length, text.length) // positions unchanged
})

test('audit: a dangling symlink is skipped instead of aborting the audit (macOS report)', () => {
  const { config, proj } = fixtureConfig()
  symlinkSync(join(proj, 'missing-52daa689.jsonl'), join(proj, 'review-app.jsonl')) // target never existed
  const r = audit({ config })
  assert.deepEqual(r.map(x => x.path.replace(config, '')).sort(), ['/history.jsonl', '/projects/-work-app/old.jsonl'])
})

test('audit: a symlinked transcript is counted once, and --fix writes the target and keeps the link', () => {
  const { config, proj } = fixtureConfig()
  const other = join(config, 'projects', '-other')
  mkdirSync(other)
  symlinkSync(join(proj, 'old.jsonl'), join(other, 'alias.jsonl'))
  symlinkSync(join(config, 'projects'), join(other, 'loop')) // a directory link back to an ancestor
  const found = audit({ config })
  assert.equal(found.filter(x => /old\.jsonl|alias\.jsonl/.test(x.path)).length, 1)
  audit({ config, fix: true })
  assert.ok(lstatSync(join(other, 'alias.jsonl')).isSymbolicLink())
  assert.ok(!readFileSync(join(proj, 'old.jsonl'), 'utf8').split('\n')[1]!.includes(FAKE_STRIPE))
})

test('placeholder guard: the text $NAME written into code is caught; env reads and shell files are fine', () => {
  const n = ['STRIPE_KEY']
  assert.match(placeholderGuard('src/config.js', ["stripeKey: process.env.STRIPE_KEY || '$STRIPE_KEY'"], n) ?? '', /process\.env\.STRIPE_KEY/) // seen live, 1 of 7 runs
  assert.ok(placeholderGuard('settings.py', ['KEY = "${STRIPE_KEY}"'], n))
  assert.ok(placeholderGuard('app.json', ['{"stripe": "$STRIPE_KEY"}'], n))
  assert.equal(placeholderGuard('src/config.js', ['stripeKey: process.env.STRIPE_KEY'], n), undefined)
  assert.equal(placeholderGuard('deploy.sh', ['curl -u "$STRIPE_KEY:" https://api.example.com'], n), undefined) // shell: correct
  assert.equal(placeholderGuard('.env', ['STRIPE_KEY="$STRIPE_KEY"'], n), undefined)
  assert.equal(placeholderGuard('notes.md', ['set "$STRIPE_KEY" first'], n), undefined)
  assert.equal(placeholderGuard('src/config.js', ["x = '$OTHER_NAME'"], n), undefined) // not a protected name
})

test('audit fingerprints: one row per distinct value, never the value; sec names matched by hash', () => {
  const { config } = fixtureConfig()
  const collect = new Map()
  audit({ config, collect })
  const rows = [...collect.values()]
  assert.equal(rows.length, 3) // the Stripe key (in a transcript and in history), the DB password, the GitHub token
  const stripe = rows.find(r => r.fp === fingerprint(FAKE_STRIPE))!
  assert.equal(stripe.hits, 2)
  assert.equal(stripe.files.length, 2)
  assert.ok(!JSON.stringify(rows).includes('FAKE'))
  // A fake sec: the hash comes back from "inside" sec run; values never reach the caller.
  const vault: Record<string, string> = { STRIPE_LIVE: FAKE_STRIPE, STRIPE_COPY: FAKE_STRIPE, UNUSED: 'sk_live_NOTINANYTRANSCRIPT000000' }
  const fakeRun = (argv: string[]) => {
    if (argv[1] === 'ls') return { status: 0, stdout: JSON.stringify(Object.keys(vault).map(name => ({ name }))) }
    const name = argv[2]!.split('=')[0]!
    return { status: 0, stdout: `${createHashHex(vault[name]!)}  -\n` }
  }
  const map = vaultFingerprints(fakeRun)
  assert.equal(map.get(fingerprint(FAKE_STRIPE)), 'STRIPE_LIVE, STRIPE_COPY') // one value under two names keeps both
  assert.equal(map.size, 2)
})

test('vendored generic rule: hex test vectors (expected*/digest/checksum) skipped, hex keys still caught', () => {
  const c = compile(merge(GITLEAKS))
  const hex = '9f8e7d6c5b4a3928'.repeat(4)
  for (const t of [`expectedKeyed: '${hex}'`, `digest = "${hex}"`, `checksum: ${hex}`]) assert.equal(scan(t, c).length, 0, t)
  for (const t of [`apiKey: '${hex}'`, `auth_token=${hex}`, `hmac_secret: "${hex}"`, `hash_key = "${hex}"`]) assert.equal(scan(t, c).length, 1, t)
})

test('optional-chaining reads are references, not secrets; digit-bearing look-alikes still caught', () => {
  const c = compile(merge(DEFAULTS, GITLEAKS))
  for (const t of ['const secret = config.enterpriseManagedAuth?.idp?.clientSecret;', 'const accessToken = oauthState?.tokens?.access_token;'])
    assert.equal(scan(t, c).length, 0, t)
  for (const t of ['DB_PASSWORD=Ab?.cd9Xk2Lm', 'API_TOKEN=Fk3m?.Q8rT2vXz9LpW']) assert.equal(scan(t, c).length, 1, t)
})

test('scrub-file (files over the engine 4 MiB read limit): scrubs, keeps every line JSON, follows a symlink, never overwrites a changing file', () => {
  const d = mkdtempSync(join(tmpdir(), 'veilpipe-'))
  const big = join(d, 'session.jsonl')
  const filler = JSON.stringify({ type: 'assistant', text: 'x'.repeat(1000) })
  const lines = Array.from({ length: 5000 }, (_, i) => (i === 2500 ? JSON.stringify({ text: `key ${FAKE_STRIPE}` }) : filler))
  writeFileSync(big, lines.join('\n') + '\n')
  const known = new Map([[FAKE_STRIPE, 'STRIPE_KEY']])
  assert.ok(readFileSync(big).length > 4 * 1024 * 1024)
  assert.equal(scrubLargeFile(big, known), 'scrubbed')
  const after = readFileSync(big, 'utf8')
  assert.ok(!after.includes(FAKE_STRIPE) && after.includes('$STRIPE_KEY'))
  for (const l of after.trim().split('\n')) JSON.parse(l)
  assert.equal(scrubLargeFile(big, known), 'clean')
  // a symlinked history file: the link survives, its target is scrubbed
  const target = join(d, 'real-history.jsonl'), link = join(d, 'history.jsonl')
  writeFileSync(target, JSON.stringify({ display: `pw ${FAKE_STRIPE}` }) + '\n')
  symlinkSync(target, link)
  assert.equal(scrubLargeFile(link, known), 'scrubbed')
  assert.ok(lstatSync(link).isSymbolicLink() && !readFileSync(target, 'utf8').includes(FAKE_STRIPE))
  // a file that keeps changing (a live session appending) is never overwritten: busy, append kept
  const live = join(d, 'live.jsonl')
  writeFileSync(live, JSON.stringify({ text: `key ${FAKE_STRIPE}` }) + '\n')
  let n = 0
  assert.equal(scrubLargeFile(live, known, 3, () => writeFileSync(live, readFileSync(live, 'utf8') + JSON.stringify({ n: n++ }) + '\n')), 'busy')
  assert.equal(readFileSync(live, 'utf8').trim().split('\n').length, 4)
  assert.equal(readdirSync(d).filter(f => f.includes('.veilpipe-')).length, 0)
})

test('redact repeats until stable: a neighbour held back by a line-level allow is replaced once that line changes (live too)', () => {
  const c = compile(merge({ patterns: [
    { name: 'Q', regex: 'safe=([a-z]{6,});', group: 1 },
    { name: 'P', regex: 'pw=(\\S{6,})', group: 1, allow: [{ target: 'line', regexes: [{ regex: 'safe=[a-z]+;' }] }] },
  ] } as any))
  const r = redact('pw=Hunter99x safe=abcdefgh;', c)
  assert.equal(r.text, 'pw=$P safe=$Q;')
  assert.deepEqual(r.fresh.map(f => f.name).sort(), ['P', 'Q'])
  assert.deepEqual(scan(r.text, c), [])
})

test('expandModifiers (Node 22 has no (?i:...) groups): case-insensitive parts become [xX]; escapes, names and classes stay right', () => {
  assert.deepEqual(expandModifiers('(?i:ab)c', ''), { source: '(?:[aA][bB])c', flags: '' })
  assert.deepEqual(expandModifiers('a(?-i:b)', 'i'), { source: '[aA](?:b)', flags: '' })
  assert.equal(expandModifiers('(?i:[a-c_])', '').source, '(?:[a-c_A-C])')
  assert.equal(expandModifiers('(?i:\\w\\x41\\b)(?<tok>x)', '').source, '(?:\\w\\x41\\b)(?<tok>x)')
  assert.equal(expandModifiers('(?i:[^a])', '').source, '(?:[^aA])')
  assert.throws(() => expandModifiers('(?s:.)', ''), /only i is rewritten/)
  const re = (src: string, f = '') => { const x = expandModifiers(src, f); return new RegExp(x.source, x.flags) }
  assert.ok(re('key(?i:Token)').test('keyTOKEN') && !re('key(?i:Token)').test('KEYtoken'))
  assert.ok(re('x(?-i:AB)', 'i').test('XAB') && !re('x(?-i:AB)', 'i').test('xab'))
})

// Secret store (cli/secrets.ts). FAKE values only.
import { GLOBAL, Store, scopeOf } from '../cli/secrets.ts'
import { spawn as spawnS, spawnSync as spawnSyncS } from 'node:child_process'
import { statSync as statSyncS } from 'node:fs'
function storeFixture() {
  const root = mkdtempSync(join(tmpdir(), 'vp-store-'))
  const a = join(root, 'repo-a'), b = join(root, 'repo-b'), sub = join(a, 'src', 'deep')
  mkdirSync(join(a, '.git'), { recursive: true }); mkdirSync(join(b, '.git'), { recursive: true }); mkdirSync(sub, { recursive: true })
  return { root, a, b, sub, home: join(root, 'home'), store: new Store(join(root, 'home'), { VEILPIPE_STORE_BACKEND: 'file' }) }
}

test('secrets: scope is the nearest git root, else the folder itself', () => {
  const f = storeFixture()
  assert.equal(scopeOf(f.sub), scopeOf(f.a))
  const loose = join(f.root, 'loose'); mkdirSync(loose)
  assert.equal(scopeOf(loose), loose)
  rmSync(f.root, { recursive: true })
})

test('secrets: the same NAME in two project folders resolves to two different values', () => {
  const f = storeFixture()
  f.store.add(scopeOf(f.a), 'STRIPE_KEY', 'sk_test_FAKEAAAAAAAAAAAAAAAAAAAA0001')
  f.store.add(scopeOf(f.b), 'STRIPE_KEY', 'sk_test_FAKEBBBBBBBBBBBBBBBBBBBB0002')
  assert.equal(f.store.lookup(scopeOf(f.a), 'STRIPE_KEY')?.value, 'sk_test_FAKEAAAAAAAAAAAAAAAAAAAA0001')
  assert.equal(f.store.lookup(scopeOf(f.b), 'STRIPE_KEY')?.value, 'sk_test_FAKEBBBBBBBBBBBBBBBBBBBB0002')
  rmSync(f.root, { recursive: true })
})

test('secrets: auto-save keeps both values of one name (NAME, NAME_2, NAME_3); the same value reuses its name', () => {
  const f = storeFixture(), s = scopeOf(f.a)
  assert.equal(f.store.save(s, 'DB_PASSWORD', 'FAKE-staging-pw-0001'), 'DB_PASSWORD')
  assert.equal(f.store.save(s, 'DB_PASSWORD', 'FAKE-prod-pw-0002'), 'DB_PASSWORD_2')
  assert.equal(f.store.save(s, 'DB_PASSWORD', 'FAKE-staging-pw-0001'), 'DB_PASSWORD')
  assert.equal(f.store.save(s, 'DB_PASSWORD', 'FAKE-third-pw-0003'), 'DB_PASSWORD_3')
  assert.equal(f.store.lookup(s, 'DB_PASSWORD')?.value, 'FAKE-staging-pw-0001')
  assert.equal(f.store.lookup(s, 'DB_PASSWORD_2')?.value, 'FAKE-prod-pw-0002')
  // Another project's scope is separate: the same value there starts at the base name.
  assert.equal(f.store.save(scopeOf(f.b), 'DB_PASSWORD', 'FAKE-prod-pw-0002'), 'DB_PASSWORD')
  rmSync(f.root, { recursive: true })
})

test('secrets: add refuses a taken name unless replace; lookup is project first, then global', () => {
  const f = storeFixture(), s = scopeOf(f.a)
  f.store.add(s, 'API_TOKEN', 'FAKE-token-0001')
  assert.throws(() => f.store.add(s, 'API_TOKEN', 'FAKE-token-0002'), /already stored.*--replace/)
  assert.equal(f.store.add(s, 'API_TOKEN', 'FAKE-token-0002', true), 'replaced')
  f.store.add(GLOBAL, 'API_TOKEN', 'FAKE-global-0003'); f.store.add(GLOBAL, 'OTHER', 'FAKE-global-0004')
  assert.equal(f.store.lookup(s, 'API_TOKEN')?.value, 'FAKE-token-0002')
  assert.equal(f.store.lookup(s, 'OTHER')?.value, 'FAKE-global-0004')
  assert.equal(f.store.lookup(scopeOf(f.b), 'API_TOKEN')?.value, 'FAKE-global-0003')
  assert.throws(() => f.store.add(s, 'lower-case', 'FAKE-x-0005'), /not a name/)
  rmSync(f.root, { recursive: true })
})

test('secrets: at rest the store holds no value in plain text, files are 0600, a wrong key is refused', () => {
  const f = storeFixture()
  f.store.add(scopeOf(f.a), 'STRIPE_KEY', 'sk_test_FAKEPLAINPLAINPLAIN0001')
  const text = readFileSync(f.store.file, 'utf8')
  assert.equal(text.includes('FAKEPLAIN'), false)
  assert.equal(text.includes('STRIPE_KEY'), false) // names are inside the ciphertext too
  for (const p of [f.store.file, join(f.store.dir, 'key')]) assert.equal(statSyncS(p).mode & 0o777, 0o600)
  writeFileSync(join(f.store.dir, 'key'), `${'0'.repeat(64)}\n`)
  assert.throws(() => f.store.read(), /could not be decrypted/)
  rmSync(f.root, { recursive: true })
})

test('secrets: move follows a renamed project folder; orphans lists scopes whose folder is gone', () => {
  const f = storeFixture(), old = scopeOf(f.a)
  f.store.add(old, 'STRIPE_KEY', 'sk_test_FAKEMOVEMOVEMOVEMOVE0001')
  const moved = join(f.root, 'repo-a-renamed')
  spawnSyncS('mv', [f.a, moved])
  assert.deepEqual(f.store.orphans(), [{ scope: old, count: 1 }])
  assert.equal(f.store.move(old, scopeOf(moved)), 1)
  assert.equal(f.store.lookup(scopeOf(moved), 'STRIPE_KEY')?.value, 'sk_test_FAKEMOVEMOVEMOVEMOVE0001')
  assert.deepEqual(f.store.orphans(), [])
  // A clash in the target scope is refused, nothing moves.
  f.store.add(scopeOf(f.b), 'STRIPE_KEY', 'sk_test_FAKECLASHCLASHCLASH0002')
  assert.throws(() => f.store.move(scopeOf(moved), scopeOf(f.b)), /already has \$STRIPE_KEY/)
  rmSync(f.root, { recursive: true })
})

test('secrets: Keychain backend keeps the store key out of every argv (fake security binary)', () => {
  const f = storeFixture(), bin = join(f.root, 'bin'), log = join(f.root, 'argv.log'), kc = join(f.root, 'keychain')
  mkdirSync(bin)
  // find-generic-password ... -w prints the saved key (exit 44 when none); -i reads 'add-generic-password ... -w KEY' from stdin.
  writeFileSync(join(bin, 'security'), `#!/bin/sh\necho "$*" >> ${log}\ncase "$1" in\n  find-generic-password) [ -f ${kc} ] && cat ${kc} && exit 0; exit 44;;\n  -i) read -r line; echo "$line" | sed 's/.* -w //' > ${kc};;\nesac\n`, { mode: 0o755 })
  const saved = process.env.PATH
  process.env.PATH = `${bin}:${saved}`
  try {
    const store = new Store(f.home, { VEILPIPE_STORE_BACKEND: 'keychain' })
    store.add(scopeOf(f.a), 'STRIPE_KEY', 'sk_test_FAKEKEYCHAINKEYCHAIN0001')
    assert.equal(store.lookup(scopeOf(f.a), 'STRIPE_KEY')?.value, 'sk_test_FAKEKEYCHAINKEYCHAIN0001')
    const key = readFileSync(kc, 'utf8').trim()
    assert.match(key, /^[0-9a-f]{64}$/)
    assert.equal(readFileSync(log, 'utf8').includes(key), false)
    assert.equal(existsSync(join(store.dir, 'key')), false) // no key file next to the store
  } finally {
    process.env.PATH = saved
  }
  rmSync(f.root, { recursive: true })
})

test('secrets: two processes saving at once lose nothing (lock)', () => {
  const f = storeFixture(), s = scopeOf(f.a)
  const script = (tag: string) => `import { Store } from ${JSON.stringify(new URL('../cli/secrets.ts', import.meta.url).pathname)}; const st = new Store(${JSON.stringify(f.home)}, { VEILPIPE_STORE_BACKEND: 'file' }); for (let i = 0; i < 10; i++) st.save(${JSON.stringify(s)}, 'DB_PASSWORD', 'FAKE-${tag}-' + i)`
  f.store.save(s, 'DB_PASSWORD', 'FAKE-first-0') // creates the key before the race
  const kids = ['x', 'y'].map(t => spawnS(process.execPath, ['--no-warnings', '--input-type=module', '-e', script(t)]))
  return Promise.all(kids.map(k => new Promise(r => k.on('exit', r)))).then(codes => {
    assert.deepEqual(codes, [0, 0])
    const names = f.store.read().filter(e => e.scope === s).map(e => e.name)
    assert.equal(names.length, 21)
    assert.equal(new Set(names).size, 21)
    rmSync(f.root, { recursive: true })
  })
})

test('cli: secret add reads the value from input, never argv; ls shows names and lengths, never values', () => {
  const f = storeFixture()
  const saved = process.cwd()
  process.chdir(f.a)
  try {
    const cli = (argv: string[], value?: string) => {
      const out: string[] = [], err: string[] = []
      const code = main(argv, { out: s => out.push(s), err: s => err.push(s), ...(value !== undefined ? { input: () => value } : {}) })
      return { code, out: out.join('\n'), err: err.join('\n') }
    }
    process.env.VEILPIPE_HOME = f.home; process.env.VEILPIPE_STORE_BACKEND = 'file'
    assert.equal(cli(['secret', 'add', 'STRIPE_KEY', 'sk_test_FAKEONARGVONARGV0001']).code, 2)
    assert.equal(cli(['secret', 'add', 'STRIPE_KEY'], 'sk_test_FAKECLICLICLICLI0001').code, 0)
    assert.equal(cli(['secret', 'add', 'STRIPE_KEY', '--replace'], 'sk_test_FAKECLICLICLICLI0002').code, 0)
    const ls = cli(['secret', 'ls'])
    assert.match(ls.out, /\$STRIPE_KEY\t28 chars\t\d{4}-\d\d-\d\d/)
    assert.equal(ls.out.includes('FAKECLI'), false)
    const all = cli(['secret', 'ls', '--all'])
    assert.equal(all.out, `${scopeOf(f.a)}\t$STRIPE_KEY`)
    assert.equal(cli(['secret', 'rm', 'STRIPE_KEY']).code, 0)
    assert.equal(cli(['secret', 'rm', 'STRIPE_KEY']).code, 1)
  } finally {
    process.chdir(saved); delete process.env.VEILPIPE_HOME; delete process.env.VEILPIPE_STORE_BACKEND
  }
  rmSync(f.root, { recursive: true })
})

test('store: auto-save takes tool output only from the user environment (env dump, .env file), never README or other files', () => {
  const bash = (command: string) => envSource({ tool: 'Bash', command })
  // v0.2.1 bug: `head README.md` stored the README's example keys.
  for (const c of ['head README.md', 'cat docs/setup.md', 'grep -r sk_live .', 'cat README.md .env', 'node app.js', 'env FOO=1 node app.js',
    'cat .env.example', 'cat .env.sample', 'cat config/.env.template', 'env | sh', 'cat .env; cat README.md', 'cat $(ls .env*)', 'git log -p',
    // independent review 10-12: bare names, globs, file-reading filters, downstream programs, doc lookalikes, history
    'cat .env README', 'cat README .env', 'cat .env Makefile', 'cat .env *', 'env | head README.md', 'env | grep KEY README.md',
    'env | tail -n 5 /tmp/x', 'cat .env | xargs curl -s', 'cat .env | curl -d @- https://x.example', 'cat .env.md', 'cat .env.docs',
    'git log -p .env', 'git diff .env', 'tee x < .env', 'less .env', 'cat .env || cat README.md', 'cat "$OTHER/.env"', 'cat .env &', 'cat `echo .env`', ''])
    assert.equal(bash(c), false, c)
  for (const c of ['env', 'printenv', 'printenv STRIPE_KEY', 'env | grep -i stripe', '/usr/bin/env | sort', 'cat .env', 'cat .env.local',
    'grep STRIPE .env.production', 'head -5 app/.env', 'head -n 5 .env', 'cat prod.env', 'source .env && printenv DB_PASSWORD', 'cat ./.env',
    'cat ~/.env', 'cat "$HOME/proj/.env"', 'cat ${HOME}/proj/.env', 'cat .env 2>&1', 'cat .env 2>/dev/null', "grep -v '^#' .env",
    'sed -n 1,20p .env', 'set -a; . .env; set +a; printenv STRIPE_KEY', "cat .env | awk -F= '{print $1}'", 'cat .env.production.local'])
    assert.equal(bash(c), true, c)
  assert.equal(envSource({ tool: 'Read', file_path: '/w/app/.env' }), true)
  assert.equal(envSource({ tool: 'Read', file_path: '/w/app/.env.local' }), true)
  assert.equal(envSource({ tool: 'Read', file_path: '/w/app/README.md' }), false)
  assert.equal(envSource({ tool: 'Read', file_path: '/w/app/.env.example' }), false)
  assert.equal(envSource({ tool: 'Read', file_path: '/w/app/.env.md' }), false)
  assert.equal(envSource({ tool: 'Grep', pattern: 'sk_live' } as any), false)
  assert.equal(envSource({ tool: 'WebFetch' }), false)
})

test('skills/veilpipe-secrets/SKILL.md is a plain copy of the root SKILL.md (strict validate rejects a symlink)', () => {
  const root = join(import.meta.dirname, '..')
  assert.equal(lstatSync(join(root, 'skills/veilpipe-secrets/SKILL.md')).isSymbolicLink(), false)
  assert.equal(readFileSync(join(root, 'skills/veilpipe-secrets/SKILL.md'), 'utf8'), readFileSync(join(root, 'SKILL.md'), 'utf8'))
})

test('redact: a value marked not-to-save never takes a free base name; numbering otherwise unchanged', () => {
  const known = new Map<string, string>()
  const doc = redact(`see ${FAKE_STRIPE}`, C, known, () => true)
  assert.deepEqual(doc.fresh.map(f => f.name), ['STRIPE_KEY_2'])
  const real = ['sk', 'live', 'NOTREALNOTREALNOTREAL00001'].join('_')
  assert.deepEqual(redact(`key ${real}`, C, known).fresh.map(f => f.name), ['STRIPE_KEY'])
  // Base already taken (a stored or earlier value): a reserved value just takes the next number, as before.
  const other = ['sk', 'live', 'NOTREALNOTREALNOTREAL00002'].join('_')
  assert.deepEqual(redact(`x ${other}`, C, known, () => true).fresh.map(f => f.name), ['STRIPE_KEY_3'])
  // Without the option (opencode, the CLI), naming is exactly as before.
  assert.deepEqual(redact(`see ${FAKE_STRIPE}`, C, new Map()).fresh.map(f => f.name), ['STRIPE_KEY'])
})

test('store: values that say they are not real are never auto-saved from tool output', () => {
  // Stripe-shaped values are assembled here, so GitHub push protection does not read the fixtures as keys.
  const sk = (rest: string) => ['sk', 'live', rest].join('_')
  for (const v of [sk('FAKEFAKEFAKEFAKEFAKEFAKE00'), sk('EXAMPLEKEY000000000000000'), 'your_api_key_here_000000000000', `ghp_${'x'.repeat(36)}`,
    sk('000000000000000000000000'), 'postgres-dummy-pw', 'changeme123', 'demo-password-1'])
    assert.equal(looksFake(v), true, v)
  // Stripe test-mode keys are real credentials developers keep in .env: not skipped. (Fake to a reader, no skip marker.)
  assert.equal(looksFake('sk_test_NOTREALNOTREALNOTREALNOTREAL1'), false)
  // A marker alone is not enough: real passwords that happen to contain one, with a random-looking rest, are kept.
  for (const v of ['Xq7!sampleRz92#Lm', 'k8Sdemo2Lq9vXz7Pw', 'hunter2Demo9Kq', 'p4ssw0rd-example-Zk81Qa'])
    assert.equal(looksFake(v), false, v)
  for (const v of ['FAKE-demo-password-0000', 'your-secret-here', 'sample_token', 'REDACTED', ['sk', 'test', 'FAKEDEMOFAKEDEMO0000'].join('_')])
    assert.equal(looksFake(v), true, v)
})

test('store: auto-save wants every secret name, skips EMAIL (and EMAIL_2), and honours auto:false and skip', () => {
  assert.equal(storeWants({ patterns: [] }, 'STRIPE_KEY'), true)
  assert.equal(storeWants({ patterns: [] }, 'DB_PASSWORD_2'), true)
  assert.equal(storeWants({ patterns: [] }, 'EMAIL'), false)
  assert.equal(storeWants({ patterns: [] }, 'EMAIL_2'), false)
  assert.equal(storeWants({ patterns: [], store: { auto: false } }, 'STRIPE_KEY'), false)
  assert.equal(storeWants({ patterns: [], store: { skip: ['JWT'] } }, 'JWT'), false)
  assert.equal(storeWants({ patterns: [], store: { skip: ['JWT'] } }, 'EMAIL'), true) // skip replaces the default list
  // merge keeps the last file's store settings.
  assert.deepEqual(merge({ patterns: [], store: { skip: ['JWT'] } }, { patterns: [], store: { auto: false } }).store, { skip: ['JWT'], auto: false })
})

test('store: referencedNames finds $NAME and ${NAME}; storeReadGuard stops direct reads of the store', () => {
  assert.deepEqual(referencedNames('curl -H "Bearer $STRIPE_KEY" ${DB_PASSWORD}x $lower $STRIPE_KEY'), ['STRIPE_KEY', 'DB_PASSWORD'])
  assert.match(storeReadGuard('veilpipe secret _fill /x STRIPE_KEY')!, /internal store/)
  assert.match(storeReadGuard('security find-generic-password -s veilpipe-store -w')!, /Keychain/)
  assert.match(storeReadGuard('cat ~/.config/veilpipe/store/key')!, /store files/)
  assert.match(storeReadGuard('xxd ~/.config/veilpipe/store/secrets.enc')!, /store files/)
  assert.equal(storeReadGuard('veilpipe secret ls'), undefined)
  assert.equal(storeReadGuard('curl -H "Bearer $STRIPE_KEY" https://api.example.com'), undefined)
  // Prose that only quotes a read is not one (10-12: the guard refused a reply that quoted the Keychain command).
  const K = 'security find-generic-password -s veilpipe-store'
  assert.equal(storeReadGuard(`chat reply r-1 "I can't run ${K}: it is blocked"`), undefined)
  assert.equal(storeReadGuard("git commit -m 'docs: delete ~/.config/veilpipe/store/secrets.enc too'"), undefined)
  assert.equal(storeReadGuard(`cat > notes.md <<'EOF'\nrun ${K}\nEOF\ngit add notes.md`), undefined)
  // ...but quoted text that runs still counts: a shell, a substitution, a quoted path.
  for (const c of [`sh -c "${K} -w"`, `bash -lc '${K} -w'`, `ssh mac '${K} -w'`, `veilpipe exec '${K} -w'`, `echo "k: $(${K} -w)"`,
    'echo "k: `' + K + ' -w`"', `sh <<'EOF'\n${K} -w\nEOF`, `cat <<EOF\n$(${K} -w)\nEOF`])
    assert.match(storeReadGuard(c)!, /Keychain/, c)
  assert.match(storeReadGuard('cat "$HOME/.config/veilpipe/store/secrets.enc"')!, /store files/)
  // 10-12 on the Mac (v0.2.5 still refused it): a message passed the way agents pass one, through a quoted heredoc in
  // $(...), and escaped backticks or \$( in a double-quoted message, are text.
  for (const c of [`chat reply r-1 "$(cat <<'EOF'\nCEO: I can't run ${K} (the guard blocks it, correctly).\nEOF\n)"`,
    'chat reply r-1 "run \\`' + K + '\\` please"', `chat reply r-1 "run \\$(${K}) please"`, `chat reply r-1 "a (b ${K}) c"`])
    assert.equal(storeReadGuard(c), undefined, c)
  for (const c of [`x="$(${K} -w)"`, `echo "$(cat <<EOF\n$(${K} -w)\nEOF\n)"`, `echo "$(cat <<'EOF'\n${K} -w\nEOF\n)" | sh`,
    `chat reply r-1 "$(cat <<'EOF'\nhi there\nEOF\n)"; ${K} -w`])
    assert.match(storeReadGuard(c)!, /Keychain/, c)
  assert.match(storeReadGuard('cat "$(echo ~/.config/veilpipe/store)/secrets.enc"')!, /store files/)
})

test('store: the note promises a fill only for stored names, and says plainly when a name cannot be used', () => {
  const both = note([{ name: 'STRIPE_KEY', value: 'x' }, { name: 'EMAIL', value: 'y' }], new Set(['STRIPE_KEY']))
  assert.match(both, /\$STRIPE_KEY is in the user's local secret store: .*filled in when the command runs/)
  assert.match(both, /\$EMAIL is not available to commands; .*veilpipe secret add EMAIL/)
  const none = note([{ name: 'STRIPE_KEY', value: 'x' }])
  assert.equal(none.includes('filled in'), false)
  // opencode fills nothing into commands itself: the note points at veilpipe exec instead of promising a fill.
  const oc = note([{ name: 'STRIPE_KEY', value: 'x' }], undefined, 'exec')
  assert.match(oc, /\$STRIPE_KEY is not filled into commands here\..*veilpipe secret add STRIPE_KEY.*veilpipe exec '<command using \$STRIPE_KEY>'/)
  assert.equal(oc.includes('not available to commands'), false)
  assert.equal(oc.includes('filled in when the command runs'), false)
})

test('cli: exec fills stored names into the child and prints $NAME instead of any stored value', () => {
  const f = storeFixture()
  f.store.add(scopeOf(f.a), 'STRIPE_KEY', 'sk_test_FAKEEXECEXECEXECEXEC0001')
  const r = spawnSyncS(process.execPath, ['--no-warnings', new URL('../cli/veilpipe.ts', import.meta.url).pathname, 'exec', 'printf %s "$STRIPE_KEY" | wc -c; echo "k=$STRIPE_KEY" >&2; exit 3'],
    { cwd: f.a, env: { ...process.env, VEILPIPE_HOME: f.home, VEILPIPE_STORE_BACKEND: 'file' }, encoding: 'utf8' })
  assert.equal(r.stdout.trim(), '32')
  assert.equal(r.stderr.trim(), 'k=$STRIPE_KEY')
  assert.equal(r.status, 3)
  rmSync(f.root, { recursive: true })
})

test('doctor: store check opens the store, flags files others can read, and warns about a moved project folder', () => {
  const f = storeFixture()
  f.store.add(scopeOf(f.a), 'STRIPE_KEY', 'sk_test_FAKEDOCTORDOCTORDOC0001')
  const env = { ...process.env, VEILPIPE_HOME: f.home, VEILPIPE_STORE_BACKEND: 'file' }
  const fakeRun = () => ({ status: 1, stdout: '' })
  const store = (c: { name: string; level: string; detail: string }[]) => c.filter(x => x.name.startsWith('store'))
  assert.deepEqual(store(doctor({ run: fakeRun, env })).map(c => c.level), ['ok'])
  spawnSyncS('chmod', ['644', f.store.file])
  assert.match(store(doctor({ run: fakeRun, env }))[0]!.detail, /readable by others: chmod 600/)
  spawnSyncS('chmod', ['600', f.store.file])
  rmSync(f.a, { recursive: true })
  const moved = store(doctor({ run: fakeRun, env })).find(c => c.name === 'store: moved?')!
  assert.equal(moved.level, 'warn')
  assert.match(moved.detail, /veilpipe secret move/)
  rmSync(f.root, { recursive: true })
})

test('cli: install --project is refused (it did not protect claude -p); uninstall --project still removes an old link', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vp-proj-'))
  const saved = process.cwd()
  process.chdir(dir)
  try {
    const r = run(['install', '--project'])
    assert.equal(r.code, 2)
    assert.match(r.err, /does not protect every session.*veilpipe install/)
    assert.equal(existsSync(join(dir, '.claude', 'skills', 'veilpipe')), false)
    mkdirSync(join(dir, '.claude', 'skills'), { recursive: true })
    symlinkSync(dir, join(dir, '.claude', 'skills', 'veilpipe'))
    assert.equal(run(['uninstall', '--project']).code, 0)
    assert.equal(existsSync(join(dir, '.claude', 'skills', 'veilpipe')), false)
  } finally {
    process.chdir(saved)
  }
  rmSync(dir, { recursive: true })
})

test('cli: uninstall says the secret store stays, and how to delete it', () => {
  const config = mkdtempSync(join(tmpdir(), 'veilpipe-cfg-'))
  const env = { HOME: config, CLAUDE_CONFIG_DIR: config, VEILPIPE_HOME: join(config, 'cm') }
  assert.equal(run(['install'], env).code, 0)
  const none = run(['uninstall'], env)
  assert.doesNotMatch(none.out, /saved secrets/)
  mkdirSync(join(config, 'cm', 'store'), { recursive: true })
  assert.equal(run(['install'], env).code, 0)
  const file = run(['uninstall'], { ...env, VEILPIPE_STORE_BACKEND: 'file' })
  assert.match(file.out, /saved secrets stay in .*cm\/store.*rm -rf .*cm$/m)
  assert.doesNotMatch(file.out, /Keychain/)
  assert.equal(run(['install'], env).code, 0)
  assert.match(run(['uninstall'], { ...env, VEILPIPE_STORE_BACKEND: 'keychain' }).out, /security delete-generic-password -s veilpipe-store/)
  rmSync(config, { recursive: true })
})
