#!/bin/sh
# Veilpipe installer: clones a pinned release, links the CLI, loads the mod into new Claude Code sessions (and opencode,
# if present), then runs `veilpipe doctor`. POSIX sh; needs git and Node 22.18+. Nothing to npm install, no sudo.
#   curl -fsSL <page>/install.sh | sh           or, from a clone: sh scripts/install.sh
# Settings (env): VEILPIPE_REF (release tag, default below), VEILPIPE_DIR (default ~/.veilpipe),
#   VEILPIPE_BIN (default ~/.local/bin), VEILPIPE_REPO (default the public repo).
# Undo: veilpipe uninstall; veilpipe uninstall --opencode; rm -rf ~/.veilpipe ~/.local/bin/veilpipe
set -eu

main() {
  REF=${VEILPIPE_REF:-v0.2.1}
  DIR=${VEILPIPE_DIR:-$HOME/.veilpipe}
  BIN=${VEILPIPE_BIN:-$HOME/.local/bin}
  REPO=${VEILPIPE_REPO:-https://github.com/deemwar-products/veilpipe}

  command -v git >/dev/null 2>&1 || fail "git not found"
  command -v node >/dev/null 2>&1 || fail "node not found (Node 22.18+ needed)"
  node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=18)?0:1)' ||
    fail "Node $(node --version) is too old: 22.18+ runs the TypeScript source directly"

  if [ -d "$DIR/.git" ]; then
    say "updating $DIR to $REF"
    git -C "$DIR" fetch -q --depth 1 origin "refs/tags/$REF:refs/tags/$REF" 2>/dev/null || git -C "$DIR" fetch -q --depth 1 origin "$REF"
    git -C "$DIR" -c advice.detachedHead=false checkout -q "$REF" 2>/dev/null || git -C "$DIR" -c advice.detachedHead=false checkout -q FETCH_HEAD
  elif [ -e "$DIR" ]; then
    fail "$DIR exists and is not a veilpipe clone; move it or set VEILPIPE_DIR"
  else
    say "cloning $REF into $DIR"
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$REF" "$REPO" "$DIR"
  fi

  mkdir -p "$BIN"
  ln -sf "$DIR/bin/veilpipe" "$BIN/veilpipe"
  say "linked $BIN/veilpipe"
  "$DIR/bin/veilpipe" install
  if command -v opencode >/dev/null 2>&1; then "$DIR/bin/veilpipe" install --opencode; fi
  "$DIR/bin/veilpipe" doctor || say "doctor reported a problem above; fix it before relying on veilpipe"

  case ":$PATH:" in *":$BIN:"*) ;; *) say "add $BIN to your PATH to run 'veilpipe' by name" ;; esac
  say "done: new Claude Code sessions load veilpipe (running ones do not; restart them)"
}

say() { printf 'veilpipe-install: %s\n' "$*"; }
fail() { say "$*" >&2; exit 1; }

# The whole script is read before anything runs, so a cut-off download does nothing.
main "$@"
