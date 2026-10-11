# Veilpipe

Veilpipe is a Claude Code mod (Claude Code 2.1.287 or newer). Secrets in what you type, what tools return and files
you attach are replaced with names like `$STRIPE_KEY` before the model sees them: the model never sees the value. After
each turn it also scrubs the values it replaced from that session's transcript and from `history.jsonl`; see Limits for
what that disk scrub does not cover. It runs entirely on your machine: the mod makes no network calls of its own.

## Install (Node 22.18+; nothing to npm install)

```sh
git clone https://github.com/deemwar-products/veilpipe && cd veilpipe
ln -s "$PWD/bin/veilpipe" ~/.local/bin/veilpipe     # the CLI
veilpipe install                                     # every new Claude Code session loads the mod
```
Or in one step (clones the pinned release to ~/.veilpipe, links the CLI, installs, runs doctor): `sh scripts/install.sh`.
To try it in one session only, skip `veilpipe install` and run `claude --plugin-dir /path/to/veilpipe`.

## First 5 minutes

1. `veilpipe doctor`: versions, rules load, tests pass, installed. `veilpipe doctor --canary` also sends one fake key
   through `claude -p` (one Sonnet call on your account) and checks that the model saw `$STRIPE_KEY` and the transcript
   holds 0 copies.
2. `veilpipe audit`: read-only. Lists transcripts and prompt history that already hold secrets, by file, rule and
   count. It never prints a value. `veilpipe audit --fix` rewrites them; read the report first.
3. `veilpipe scan "<text>"`: shows what the model would see.

## Your own rules

`veilpipe add NAME 'regex' --hit EXAMPLE --miss EXAMPLE` writes `~/.config/veilpipe/patterns.json`; a project can
add `./.veilpipe/patterns.json`. `veilpipe rm NAME` switches a rule off, and `veilpipe list` shows them all. A rule
that fails its own examples is refused. A broken rules file turns the mod off loudly, and prompts are refused until it
is fixed: it never lets text through unchecked.

## opencode

Tested with opencode 1.x (1.18.35) and 2.x (2.0.22 to 2.0.26). `veilpipe install --opencode` gives opencode sessions
the same protection, from the same patterns file. It writes `00-veilpipe.ts` to opencode's plugin folder; after an
upgrade from an older kit, run it again. `veilpipe doctor` checks the install, and `veilpipe doctor --canary` also runs
`opencode/canary.sh`: a real `opencode run` with a fake key against a local mock model (no model spend). It passes only
if the model and opencode's storage hold 0 raw copies.

`veilpipe audit --opencode` is a dry run for what opencode stored before the install. It lists each table, column, row
count and file it would rewrite, by count only, and writes nothing. `veilpipe audit --opencode --fix` changes them.
Close opencode first; on 2.x also run `opencode service stop`. `--fix` first saves a private backup next to opencode's
store (`veilpipe-backup-<time>/`). If that fails, nothing changes. The backup holds the raw values, so delete it once
opencode looks right; `veilpipe doctor` warns while one is left. The store is rewritten in one transaction that
rolls back unless no match is left. opencode's
login and credential tables are never read or changed.

opencode limits:
- The TUI writes what you type to its prompt history before any plugin sees it. It is scrubbed when the message
  reaches the server, within seconds.
- A running shell command's output is stored raw until the command finishes, and the TUI may show it on screen. If
  opencode dies mid-command, run `veilpipe audit --opencode --fix`.
- 2.x writes shell output and `opencode run`'s arguments to files under its data folder before any plugin runs.
  Veilpipe masks them in place right after, and log lines written late are masked within about 0.1 s.
- Plugins that run before veilpipe see raw text, though the model and the store do not. `veilpipe doctor` names them.
- `OPENCODE_PURE=1` makes opencode load no plugins, so veilpipe is off. `veilpipe doctor` fails while it is set.
- Not tested: opencode's `share`.

## Remove it

`veilpipe uninstall` (and `veilpipe uninstall --opencode`), then delete the folder and `~/.local/bin/veilpipe`.

## Limits

The promise is about the model, not your disk. The disk scrub covers only the values veilpipe replaced, in that
session's own transcript, its subagents' transcripts and `history.jsonl`. It does not touch sessions that ran without
veilpipe, or text the model wrote itself (for example a dev password it made up for a new `.env`; it never saw yours). Run
`veilpipe audit` to see what is on disk.

Regex finds shapes, not meaning. A secret inside an unbroken base64 run over 4 KB (an image) is not scanned. The raw
text stays in the transcript or `history.jsonl` for the seconds of a turn. Files over 4 MB are scrubbed by a separate
`veilpipe` process; if another session keeps writing to the file meanwhile, that scrub waits for the next turn. Mods
are not sandboxed: read the code before you install it.

Questions and reports: io@deemwar.com

## License

Apache-2.0 (LICENSE). `rules/gitleaks.json` is derived from gitleaks' default ruleset, MIT (rules/LICENSE.gitleaks).
Tests: `node --test test/core.node.ts test/opencode.node.ts` and `veilpipe test`.
