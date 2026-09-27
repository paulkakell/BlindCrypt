# Command-line companion: 02.00.00

Requirements: Node.js 22 or later, a trusted working directory, a local filesystem supporting same-directory hard links, and the complete source or release artifact. The CLI imports the exact browser cryptographic modules and makes no network requests. Run from the repository or artifact root:

```bash
node cli/blindcrypt.mjs --help
node cli/blindcrypt.mjs --version
node cli/blindcrypt.mjs encrypt --input report.pdf --output report.blindcrypt
node cli/blindcrypt.mjs verify --input report.blindcrypt
node cli/blindcrypt.mjs decrypt --input report.blindcrypt --output restored-report.pdf
```

These commands use a hidden terminal prompt. Encryption and key generation ask for confirmation. Do not place passphrases in command arguments, command substitution, environment variables or shell history. There is deliberately no `--passphrase` argument.

## Automated secret input

`--passphrase-stdin` accepts exactly one nonempty UTF-8 line, at most 1,024 bytes, followed by EOF. An optional final LF/CRLF is removed; other leading/trailing spaces are preserved. Multiple lines, NUL, invalid UTF-8 and oversized input fail. Automation must supply an already confirmed secret. V3 normalizes NFC; legacy decryption retains original text semantics.

For example, have a trusted secret-provider process emit one line into this command. Do not replace the provider with an inline secret literal:

```bash
trusted-secret-provider | node cli/blindcrypt.mjs verify --input backup.blindcrypt --passphrase-stdin
```

`trusted-secret-provider` is an illustrative external command, not a program bundled with BlindCrypt. The CLI does not connect to or configure any provider. Protect both processes and do not enable shell tracing around secrets.

## All commands and options

| Command/option | Meaning and example |
|---|---|
| `encrypt` | Encrypt `--input report.pdf`; defaults to Strong v3 and a random output in the current directory |
| `decrypt` | Decrypt a v3/legacy input to the explicitly required `--output restored.pdf` |
| `verify` | Authenticate v3 without output; with `--identity`, verify a recipient envelope; rejects legacy completeness claims |
| `keygen` | Generate public JWK and encrypted private backup; requires `--output identity.bckey --public-output public.json` |
| `--input PATH` | Required except for keygen; example `--input "project notes.txt"` |
| `--output PATH` | New destination, required for decrypt/keygen; existing files and symlinks are refused; verify rejects it |
| `--level LEVEL` | Passphrase encryption only: `standard`, `strong`, `high`, `critical`; example `encrypt --input report.pdf --level high` |
| `--passphrase-stdin` | Read one bounded secret line from stdin rather than a terminal; not accepted for recipient encryption |
| `--recipient PATH` | Local public JWK for recipient encryption; requires `--fingerprint`; incompatible with `--level` and `--identity` |
| `--fingerprint VALUE` | Independently verified 43-character public-key fingerprint; exact match required |
| `--identity PATH` | Encrypted private backup for recipient decrypt/verify; its passphrase is prompted or read from stdin |
| `--public-output PATH` | Public JWK destination for keygen; must differ from its encrypted private destination |
| `--reveal-name` | Encryption only: when output is not explicitly supplied, use the input basename plus `.blindcrypt` instead of an opaque name |
| `--help`, `--version` | Standalone options; print usage or the exact `xx.xx.xx` application version |

Unknown options, duplicate options, incompatible combinations and missing values fail rather than being ignored. Explicit `--output` takes precedence over generated names. Public filenames/fingerprints are not secrets, but choose output paths that do not reveal sensitive subject matter when that matters.

## Recipient example

```bash
node cli/blindcrypt.mjs keygen --output identity.bckey --public-output public.json
node cli/blindcrypt.mjs encrypt --input report.pdf --output recipient.jwe --recipient public.json --fingerprint VERIFIED_FINGERPRINT
node cli/blindcrypt.mjs verify --input recipient.jwe --identity identity.bckey
node cli/blindcrypt.mjs decrypt --input recipient.jwe --output restored.pdf --identity identity.bckey
```

Replace `VERIFIED_FINGERPRINT` with the value independently confirmed with the recipient. Keygen returns the public fingerprint. Share only the public JWK, never the encrypted private backup or its passphrase. Recipient encryption supports 16 MiB and does not authenticate the sender. The profile is documented in [FORMAT.md](FORMAT.md); independent review remains pending.

## Output, failure and limits

V3 encrypt/decrypt/verify stream in bounded records up to 4 GiB. Legacy reading stays buffered at 64 MiB. Recipient encryption/decryption is bounded at 16 MiB and is not a streaming format. The input file must not be modified while it is being read. Node's file-backed Blob reader rejects detected underlying-file changes.

Writes use a random same-directory `.blindcrypt-*.partial` file opened exclusively with mode `0600`. On full success the file is synced, closed, hard-linked atomically to the requested destination, and its temporary name removed. A racing existing destination causes failure; the CLI never replaces it with `rename`. It does not automatically derive a filesystem path from authenticated metadata.

Abort/failure closes and unlinks only this operation's temporary file. In-flight SubtleCrypto work is not forcibly terminated. SIGINT/SIGTERM request cancellation. An uncatchable process kill, power loss or filesystem failure can leave a partial file or a fully committed output with its temporary link; inspect and remove those deliberately. Decrypted temporary bytes may exist on disk, and unlink is not secure erasure. Use a trusted private directory and encrypted local storage where needed. Hard-link-unsupported filesystems fail safely rather than falling back to overwrite behavior.

Keygen commits the encrypted private backup first. If the separate public export fails, the private backup is retained rather than deleted. This two-file export is not a filesystem-wide atomic transaction. Check both paths and preserve the backup; its authenticated private JWK contains the public modulus/exponent needed for a separately reviewed recovery export. Do not repeatedly regenerate an unrelated identity and assume old ciphertext will open with it.

Success is one JSON line with version, status, format and any public fingerprint or legacy warning. No secrets, original filenames, plaintext or raw error stack are printed. Failures use stable JSON codes on stderr. Exit codes: `0` success, `1` operation failure, `2` invalid usage, `130` cancellation. `AUTHENTICATION_FAILED` does not distinguish wrong secret from modified encrypted content.

No overwrite flag, recursive filesystem traversal, automatic input deletion, network key lookup, configuration file, environment secret or database is supported. For a passphrase change without intermediate plaintext disk output use the bounded browser re-encryption workflow.
