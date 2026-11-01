# secret-sweep

A small command-line tool that finds secrets (API keys, tokens, private keys,
passwords) left in source code, before they ship. One file, Node 22, nothing
installed, no network, no dependencies (only `node:` built-in modules).

## What to build

Create exactly one file at the root of this project: **`secret-sweep.mjs`**
(an ES module script). Rule: **only the paths named here as the territory may
change** — the territory is `secret-sweep.mjs`. Do not edit `README.md` or add
any other file.

It is run as:

    node secret-sweep.mjs <folder> [--json]
    <text> | node secret-sweep.mjs --stdin [--json]

Flags and the folder may come in any order. It must work with Node 22 and
nothing installed, and with no network. It must never need `git`.

## Walking a folder

`node secret-sweep.mjs <folder>` walks every file under `<folder>` (all depths,
hidden files such as `.env` included) and reads each as UTF-8 text, line by line
(lines end at `\n`; a trailing `\r` is not part of the line; line numbers start at 1).
It skips:

* any directory named `.git` or `node_modules` (at any depth);
* symbolic links (neither followed nor read);
* binary files: a file with a NUL byte (`\0`) in its first 8192 bytes;
* files larger than 1 MB (more than 1048576 bytes; a file of exactly that size is scanned);
* files whose name ends in `.example` (for example `.env.example`): nothing in them is flagged;
* the file `.secret-sweep-ignore` at the root of `<folder>` (see below).

A file that cannot be read is skipped without stopping the run.

## What counts as a secret

A "value" is the exact text that was recognised. Each finding has a *kind*:

| kind | the value is |
|---|---|
| `aws-access-key` | `AKIA` or `ASIA` followed by exactly 16 characters of `A-Z0-9`, with no letter or digit right after it |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` followed by 36 or more of `A-Za-z0-9`; or `github_pat_` followed by 40 or more of `A-Za-z0-9_` |
| `gitlab-token` | `glpat-` followed by 20 or more of `A-Za-z0-9_-` |
| `slack-token` | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-` or `xoxs-` followed by 10 or more of `A-Za-z0-9-` |
| `stripe-key` | `sk_live_`, `sk_test_`, `rk_live_` or `rk_test_` followed by 24 or more of `A-Za-z0-9` |
| `google-api-key` | `AIza` followed by 35 or more of `A-Za-z0-9_-` |
| `anthropic-key` | `sk-ant-` followed by 20 or more of `A-Za-z0-9_-` |
| `openai-key` | `sk-` followed by 32 or more of `A-Za-z0-9_-`, where what follows `sk-` does not begin with `ant-` (this covers `sk-proj-...`) |
| `private-key` | the header line text of a private key block: `-----BEGIN ` + optional uppercase words (`RSA `, `EC `, `OPENSSH `, `ENCRYPTED `, `PGP ` ...) + `PRIVATE KEY-----` (or `PRIVATE KEY BLOCK-----` for PGP). A `PUBLIC KEY` block is not a private key |
| `password` | the value in a password assignment line, see below |
| `high-entropy` | a high-entropy string next to a word like key, secret or token, see below |

A token-shaped value (all rows above except `private-key`, `password` and
`high-entropy`) is only recognised when the character right before it is not a
letter or a digit (so `task-...` is not an `sk-` key). Greedy character classes
take the longest run.

**password**: the word `password` or `passwd` (any letter case, and it may be
the end of a longer name such as `DB_PASSWORD` or `"password"` in JSON), then an
optional closing quote, optional spaces, then `=` or `:`, optional spaces, then
the value. The word must end the name (`password_hash=` is not a password
assignment). If the value starts with a quote (`"`, `'` or a backtick), it is
the text up to the next quote of the same kind (no closing quote on the line:
not flagged). Otherwise it is the text up to the first whitespace, `,`, `;`,
quote or backtick, and a value containing `(` or `)` is code, not flagged. A
value starting with `=` or `>` is not flagged. The value must be at least 8
characters long.

**high-entropy**: a name containing `key`, `secret`, `token` or `credential`
(any letter case; the name may go on after the word, using letters, digits, `_`,
`.` or `-`), then an optional closing quote, optional spaces, then `=`, `:`,
`:=` or `=>`, optional spaces, an optional opening quote (`"`, `'` or a
backtick), then the value: the longest run of `A-Za-z0-9+/_-`, optionally
followed by trailing `=` signs. The run must end the line or be followed by
whitespace or one of `, ; ' " ` ) ] } > &` (so `src/a/b.tsx` is never a
candidate). It is flagged when it is at least 20 characters long, holds at
least one letter and at least one digit, and has a Shannon entropy of at least
3.5 bits per character (computed over its characters, log base 2).

**Placeholders are never flagged**, in any kind. A value (compared in any letter
case) is a placeholder when it:

* starts with `$`, `{{`, `<` or `%`, or contains `${` (so `${VAR}`, `$TOKEN`, `<your-key>`);
* contains one of: `your`, `example`, `placeholder`, `changeme`, `change-me`,
  `change_me`, `replace`, `dummy`, `sample`, `redacted`, `fake`, `todo`, `xxxx`,
  `****`, `process.env`, `os.environ`, `getenv`;
* contains the same character 6 or more times in a row (`00000000`);
* for `password` only: equals `password`, `secret`, `undefined` or `required`.

A secret is reported once. When several of the above cover overlapping text on a
line, the first applicable one wins, in this order: a known token shape or
private key, then `password`, then `high-entropy`. Separate secrets on one line
are all reported.

## Output

One finding per line on standard output, nothing else on standard output:

    <file>:<line> <kind> <masked>

* `<file>` is the path relative to `<folder>`, with `/` separators; for `--stdin`
  it is the text `<stdin>`, and `<line>` is the line number in the input.
* `<masked>` is the value with all but its first four characters replaced by
  `*`, one `*` for each hidden character (`ghp_` followed by 32 stars for a
  36-character token).
* Findings are sorted by file path (plain string order), then line, then
  position on the line.
* No findings: standard output is empty.

**The secret itself — the unmasked value — is never printed anywhere**: not on
standard output, not on standard error, not in `--json`, not in an error message.

`--json` replaces the lines with one JSON array on standard output (and nothing
else): one object per finding, in the same order, with the keys `file`,
`line` (a number), `kind` and `value` (the masked value). No findings gives `[]`.

## Exit status

* `0` — no finding.
* `1` — at least one finding (after the ignore list below is applied).
* `2` — usage error (no folder and no `--stdin`, folder is not a directory, an
  unknown flag, two folders); a message goes to standard error.

## Reviewed values: `.secret-sweep-ignore`

A text file listing the **fingerprints** of values that were reviewed and must
not be reported. The fingerprint of a value is the lowercase hexadecimal sha256
of the exact value (UTF-8 bytes); the file never holds the secret itself. One
fingerprint per line; blank lines and lines starting with `#` are ignored;
spaces around a line are ignored, and anything after the first whitespace on a
line is a comment; letter case of the hex does not matter. A finding whose
fingerprint is listed is not reported and does not make the exit status 1.

The file is read from `<folder>/.secret-sweep-ignore`; with `--stdin`, from
`.secret-sweep-ignore` in the current working directory. A missing file means an
empty list. (For a `private-key` finding the value, and so what is hashed, is
its header line text, e.g. `-----BEGIN RSA PRIVATE KEY-----`.)

## History: `--stdin`

`--stdin` reads all of standard input and scans it exactly as one file, with
the same rules, so old history can be checked without the tool needing git:

    git log -p | node secret-sweep.mjs --stdin

Lines of a diff begin with `+`, `-` or a space; that is simply text before the
secret, so removed lines (`-`) are scanned too. No folder is walked and none is
needed.

## Tests

Your work is judged by a hidden check that runs `node sealed/check.mjs` from the
root of a copy of the project, with Node 22, no network and no git, on its own
fixtures (made-up values only). Everything above is what it tests.
