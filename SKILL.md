---
name: veilpipe-secrets
description: Use when a command, script or config needs a secret (API key, token, password) and veilpipe has replaced it with a $NAME, or the user mentions a secret, credential, API key or .env value. How to use $NAME in commands without ever seeing, asking for or printing the value.
---

# Secrets with veilpipe

veilpipe replaces secrets with names like `$STRIPE_KEY` before you see them, and keeps the values in the user's local
secret store (encrypted, per project). You never need the value itself.

**In Bash, write the name.** A command that uses a stored name gets its value filled in when it runs:

```sh
curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com/v1/balance
psql "postgres://admin:$DB_PASSWORD@db.example.com/app" -c 'select 1'
```

- Use double quotes or none around `$NAME`; inside single quotes the shell does not expand it.
- Output that would print a stored value shows `$NAME` instead.
- veilpipe's note tells you which names are stored. A name the note says is *not available to commands* is empty in
  Bash: ask the user to run `veilpipe secret add NAME` themselves (the value goes in at their terminal, not here).

**In code and config, read the environment** (`process.env.STRIPE_KEY`, `os.environ["STRIPE_KEY"]`,
`os.Getenv("STRIPE_KEY")`). Never write the text `$STRIPE_KEY` into a file as if it were the value; it is only a name.
To run a program that reads the environment: `veilpipe exec 'npm run deploy'` fills every stored name the command uses.

**Never** ask the user to paste a value, print or echo one, slice or encode one (`${STRIPE_KEY:0:4}`, `base64`), or read
veilpipe's store files or the Keychain directly: veilpipe refuses those commands.

Useful for the user (they run these, not you): `veilpipe secret ls` (names, lengths, dates), `veilpipe secret add NAME`,
`veilpipe secret rm NAME`, `veilpipe secret move OLD_FOLDER NEW_FOLDER` after renaming a project folder.
