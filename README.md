# Veilpipe

Veilpipe is a Claude Code mod (Claude Code 2.1.287 or newer). Secrets in what you type, what tools return and files
you attach are replaced with names like `$STRIPE_KEY` before the model sees them: the model never sees the value.
After each turn it also scrubs the values it replaced from that session's transcript, its subagents' transcripts and
`history.jsonl`; see Limits for what that disk scrub does not cover. Keys you paste or keep in `.env` go into
veilpipe's own secret store, so a command that uses `$STRIPE_KEY` gets the value, in this session or a later one,
without the model ever seeing it. It runs entirely on your machine: the mod makes no network calls of its own.

## Install (Node 22.18+; nothing to npm install)

```sh
git clone https://github.com/deemwar-products/veilpipe && cd veilpipe
bin/veilpipe install                                 # every new Claude Code session loads the mod
mkdir -p ~/.local/bin && ln -sf "$PWD/bin/veilpipe" ~/.local/bin/veilpipe    # the CLI, by name
```
If `veilpipe` is then not found, `~/.local/bin` is not on your PATH (the macOS default): add it, or run `bin/veilpipe`.
Or in one step (clones the pinned release to ~/.veilpipe, links the CLI, installs, runs doctor): `sh scripts/install.sh`.
To try it in one session only, skip the install line and run `claude --plugin-dir /path/to/veilpipe`.

**Or as a Claude Code plugin:** `claude plugin marketplace add deemwar-products/veilpipe`, then
`claude plugin install veilpipe@deemwar`. That gives every session the mod but not the `veilpipe` CLI by name; for it,
`mkdir -p ~/.local/bin && ln -sf ~/.claude/plugins/marketplaces/deemwar/bin/veilpipe ~/.local/bin/veilpipe`.
Remove it with `claude plugin uninstall veilpipe@deemwar`. Use one install path, not both: where both are present the
plugin copy wins and the other is not loaded, so run `veilpipe uninstall` first if you switch.

## First 5 minutes

1. `veilpipe doctor`: versions, rules load, tests pass, installed. `veilpipe doctor --canary` also sends one fake key
   through `claude -p` (one Sonnet call on your account) and checks that the model saw `$STRIPE_KEY` and the transcript
   holds 0 copies.
2. `veilpipe audit`: read-only. Lists transcripts and prompt history that already hold secrets, by file, rule and
   count. It never prints a value. `veilpipe audit --fix` rewrites them; read the report first.
3. `veilpipe scan "<text>"`: shows what the model would see.

## Its own secret store

When veilpipe catches a value you type or paste, or one in your own environment (an `env` or `printenv` dump, or a
command that only reads `.env`, `.env.local`, `.env.production` and the like, such as `cat .env` or `grep KEY .env`),
it saves it under its `$NAME` in a local, encrypted store, scoped to the project (the nearest git root, else the
folder). Values in other files and command output (a README, docs, source code, `git log`), or from a command that
reads anything besides those files, are still replaced but never saved, and neither is a value that says it is not
real (FAKE, EXAMPLE, DEMO, `your_key`, `xxxxxxxx` with nothing random beside them; veilpipe says when it skips one
from `.env`); add one yourself with `veilpipe secret add NAME`. A Bash command
the model writes with `$STRIPE_KEY` then gets the value filled in when it runs, in this session or a new one; the
model, the command text and the transcript only ever hold the name. Output that prints a stored value shows `$NAME`
instead.

- **The store:** one AES-256-GCM file, `~/.config/veilpipe/store/secrets.enc` (mode 600). Its key is in the macOS
  Keychain (`veilpipe-store`), or in a mode-600 key file next to it on Linux. Nothing is synced between machines.
- **Two values, one name** (a staging and a prod `DB_PASSWORD`): both are kept, as `$DB_PASSWORD` and `$DB_PASSWORD_2`,
  and veilpipe tells the model which is which. The same value seen again keeps its name. Nothing is overwritten.
  A value veilpipe will not save (a README's example key) takes the next number, so `$STRIPE_KEY` stays free for
  your real key.
- **Two projects, one name:** each project folder has its own `$STRIPE_KEY`. `--global` adds a fallback for every project.
- **You manage it** (values come from stdin or a hidden prompt, never the command line):

```sh
veilpipe secret ls                    # names, lengths and dates for this project; never values
veilpipe secret add STRIPE_KEY        # add one yourself (--replace to change it, --global for every project)
veilpipe secret rm STRIPE_KEY
veilpipe secret move ~/old/app ~/new/app    # a project folder was moved or renamed
veilpipe exec 'npm run deploy'        # run a command with the stored names it uses filled in, output scrubbed
```

- **Opt out:** `"store": { "auto": false }` in a patterns file (or `VEILPIPE_NO_STORE=1`); then nothing is saved and
  veilpipe tells the model plainly that commands can't use the value. Emails are never saved (`"skip"` changes the list).
- **Agent skill:** `veilpipe-secrets` comes with it and tells the model to write `$NAME` in commands and never ask for,
  print or slice a value. Commands that read the store or the Keychain directly are refused.
- `veilpipe doctor` checks the store (key present, files private, no project folder gone missing);
  `veilpipe doctor --canary` stores a fake value, has a real session use it in a command, and removes it.

## Your own rules

`veilpipe add NAME 'regex' --hit EXAMPLE --miss EXAMPLE` writes `~/.config/veilpipe/patterns.json`; a project can
add `./.veilpipe/patterns.json`. `veilpipe rm NAME` switches a rule off, and `veilpipe list` shows them all. A rule
that fails its own examples is refused. A broken rules file turns the mod off loudly, and prompts are refused until it
is fixed: it never lets text through unchecked.

## opencode

Tested with opencode 1.x (1.18.35, 1.19.0) and 2.x (2.0.22 to 2.0.29). `veilpipe install --opencode` gives opencode
sessions the same replacement and scrub, from the same patterns file (not the secret store: see limits below). It
writes `00-veilpipe.ts` to opencode's plugin folder; after an upgrade from an older kit, run it again. `veilpipe
doctor` checks the install, and `veilpipe doctor --canary` also runs `opencode/canary.sh`: a real `opencode run` with
a fake key against a local mock model (no model spend). It passes only if the model and opencode's storage hold 0 raw
copies.

`veilpipe audit --opencode` is a dry run for what opencode stored before the install. It lists each table, column, row
count and file it would rewrite, by count only, and writes nothing. `veilpipe audit --opencode --fix` changes them.
Close opencode first; on 2.x also run `opencode service stop`. `--fix` first saves a private backup next to opencode's
store (`veilpipe-backup-<time>/`). If that fails, nothing changes. The backup holds the raw values, so delete it once
opencode looks right; `veilpipe doctor` warns while one is left. The store is rewritten in one transaction that
rolls back unless no match is left. opencode's
login and credential tables are never read or changed.

opencode limits:
- The secret store is Claude Code only for now: in opencode, values are replaced but not saved, and `$NAME` is not
  filled into the commands the model writes. A command reaches a stored value through
  `veilpipe exec '<command>'`, and veilpipe tells the model so.
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

That leaves the secret store, so a reinstall still has your saved keys. To delete them too:

```sh
rm -rf ~/.config/veilpipe                             # the encrypted store (and, on Linux, its key file)
security delete-generic-password -s veilpipe-store    # macOS only: its key in the Keychain
```

## Limits

The promise is about the model, not your disk. The disk scrub covers only the values veilpipe replaced, in that
session's own transcript, its subagents' transcripts and `history.jsonl`. It does not touch sessions that ran without
veilpipe, or text the model wrote itself (for example a dev password it made up for a new `.env`; it never saw yours). Run
`veilpipe audit` to see what is on disk.

Regex finds shapes, not meaning. A secret inside an unbroken base64 run over 4 KB (an image) is not scanned. The raw
text stays in the transcript or `history.jsonl` for the seconds of a turn. Files over 4 MB are scrubbed by a separate
`veilpipe` process; if another session keeps writing to the file meanwhile, that scrub waits for the next turn.
A tool result over 2 million characters is withheld, not scanned: the model gets
`veilpipe: output too large to scan for secrets; withheld.`, so narrow the command (`head`, `grep`) and run it again. Mods
are not sandboxed: read the code before you install it.

The store widens what one bad command can reach: a prompt-injected command in a project can use every value stored for
that project (and the global ones), not just what you pasted in that session. Output that prints a value is still
replaced, but a value a command sends over the network is out of veilpipe's sight. Turn auto-save off where that matters.

Auto-save keeps only what you type or paste and what is in your own environment or `.env` files. A real key that
lives only in another file (say `config.json`) is replaced but not saved, so commands can't use it until you run
`veilpipe secret add NAME`; veilpipe tells the model so. If your Claude Code settings deny reading `.env` files (a
`permissions.deny` rule), the session never sees those values, so nothing is saved from them either: add the ones
commands need with `veilpipe secret add NAME`.

**Want it set up for your team?** Deemwar does a one-week, fixed-price Claude Code setup: a team CLAUDE.md, hooks, and
Veilpipe on your repos, with secrets kept out of the model.
[deemwar.com/consulting](https://deemwar.com/consulting?utm_source=veilpipe&utm_medium=github-readme&utm_campaign=veilpipe)
What such a review finds, run on this repo: [sample agent-security review](https://deemwar.com/insights/veilpipe-sample-review?utm_source=veilpipe&utm_medium=github-readme&utm_campaign=veilpipe).

Questions and reports: io@deemwar.com

## License

Apache-2.0 (LICENSE). `rules/gitleaks.json` is derived from gitleaks' default ruleset, MIT (rules/LICENSE.gitleaks).
Tests: `node --test test/core.node.ts test/opencode.node.ts` and `veilpipe test`.
