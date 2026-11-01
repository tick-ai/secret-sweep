#!/usr/bin/env node
// secret-sweep: finds secrets (API keys, tokens, private keys, passwords) left in
// source code. Node built-ins only; it never prints the unmasked value.

import { createHash } from 'node:crypto';
import { readFileSync, readSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const USAGE = 'usage: node secret-sweep.mjs <folder> [--json]\n       <text> | node secret-sweep.mjs --stdin [--json]';
const IGNORE_FILE = '.secret-sweep-ignore';
const MAX_BYTES = 1048576;
const BINARY_WINDOW = 8192;

class UsageError extends Error {}

// ------------------------------------------------------------------ patterns

const NOT_ALNUM_BEFORE = '(?<![A-Za-z0-9])';
const TOKEN_KINDS = [
  { kind: 'aws-access-key', pattern: new RegExp(`${NOT_ALNUM_BEFORE}(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])`, 'g') },
  { kind: 'github-token', pattern: new RegExp(`${NOT_ALNUM_BEFORE}(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})`, 'g') },
  { kind: 'gitlab-token', pattern: new RegExp(`${NOT_ALNUM_BEFORE}glpat-[A-Za-z0-9_-]{20,}`, 'g') },
  { kind: 'slack-token', pattern: new RegExp(`${NOT_ALNUM_BEFORE}xox[bpars]-[A-Za-z0-9-]{10,}`, 'g') },
  { kind: 'stripe-key', pattern: new RegExp(`${NOT_ALNUM_BEFORE}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}`, 'g') },
  { kind: 'google-api-key', pattern: new RegExp(`${NOT_ALNUM_BEFORE}AIza[A-Za-z0-9_-]{35,}`, 'g') },
  { kind: 'anthropic-key', pattern: new RegExp(`${NOT_ALNUM_BEFORE}sk-ant-[A-Za-z0-9_-]{20,}`, 'g') },
  { kind: 'openai-key', pattern: new RegExp(`${NOT_ALNUM_BEFORE}sk-(?!ant-)[A-Za-z0-9_-]{32,}`, 'g') },
  { kind: 'private-key', pattern: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----/g },
];

const PASSWORD_WORD = /passw(?:or)?d["'`]?[ \t]*[=:]/gi;
const NAME_RUN = /[A-Za-z0-9_.-]+/g;
const ENTROPY_AFTER_NAME = /["'`]?[ \t]*(?::=|=>|=|:)[ \t]*["'`]?([A-Za-z0-9+/_-]+=*)(?=$|[\s,;'"`)\]}>&])/y;
const KEYWORDS = ['key', 'secret', 'token', 'credential'];

const PLACEHOLDER_WORDS = [
  'your', 'example', 'placeholder', 'changeme', 'change-me', 'change_me', 'replace', 'dummy',
  'sample', 'redacted', 'fake', 'todo', 'xxxx', '****', 'process.env', 'os.environ', 'getenv',
];

function isPlaceholder(value, kind) {
  const text = value.toLowerCase();
  if (text.startsWith('$') || text.startsWith('{{') || text.startsWith('<') || text.startsWith('%')) return true;
  if (text.includes('${')) return true;
  if (PLACEHOLDER_WORDS.some((word) => text.includes(word))) return true;
  if (/(.)\1{5}/su.test(text)) return true;
  if (kind === 'password' && ['password', 'secret', 'undefined', 'required'].includes(text)) return true;
  return false;
}

function shannonEntropy(text) {
  const counts = new Map();
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1);
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / total;
    bits -= p * Math.log2(p);
  }
  return bits;
}

// ------------------------------------------------------------- scanning a line

/** Candidates are { start, end, kind, value }; the first applicable kind wins an overlap. */
function scanLine(line) {
  const tokens = [];
  for (const { kind, pattern } of TOKEN_KINDS) {
    pattern.lastIndex = 0;
    for (const match of line.matchAll(pattern)) {
      tokens.push({ start: match.index, end: match.index + match[0].length, kind, value: match[0] });
    }
  }

  const passwords = [];
  PASSWORD_WORD.lastIndex = 0;
  for (const match of line.matchAll(PASSWORD_WORD)) {
    let at = match.index + match[0].length;
    while (at < line.length && (line[at] === ' ' || line[at] === '\t')) at += 1;
    if (at >= line.length) continue;
    const first = line[at];
    let value;
    let start = at;
    if (first === '"' || first === "'" || first === '`') {
      const close = line.indexOf(first, at + 1);
      if (close === -1) continue;
      start = at + 1;
      value = line.slice(start, close);
    } else {
      let end = at;
      while (end < line.length && !/[\s,;"'`]/u.test(line[end])) end += 1;
      value = line.slice(at, end);
      if (value.includes('(') || value.includes(')')) continue;
      if (value.startsWith('=') || value.startsWith('>')) continue;
    }
    if ([...value].length < 8) continue;
    passwords.push({ start, end: start + value.length, kind: 'password', value });
  }

  const entropies = [];
  NAME_RUN.lastIndex = 0;
  for (const run of line.matchAll(NAME_RUN)) {
    const lowered = run[0].toLowerCase();
    if (!KEYWORDS.some((word) => lowered.includes(word))) continue;
    ENTROPY_AFTER_NAME.lastIndex = run.index + run[0].length;
    const found = ENTROPY_AFTER_NAME.exec(line);
    if (found === null) continue;
    const value = found[1];
    if (value.length < 20 || !/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) continue;
    if (shannonEntropy(value) < 3.5) continue;
    const end = found.index + found[0].length;
    entropies.push({ start: end - value.length, end, kind: 'high-entropy', value });
  }

  const accepted = [];
  const overlaps = (a, b) => a.start < b.end && b.start < a.end;
  for (const group of [tokens, passwords, entropies]) {
    for (const candidate of group) {
      if (isPlaceholder(candidate.value, candidate.kind)) continue;
      if (accepted.some((other) => overlaps(candidate, other))) continue;
      accepted.push(candidate);
    }
  }
  return accepted.sort((a, b) => a.start - b.start);
}

function mask(value) {
  const chars = [...value];
  return chars.slice(0, 4).join('') + '*'.repeat(Math.max(0, chars.length - 4));
}

const fingerprint = (value) => createHash('sha256').update(value, 'utf8').digest('hex');

/** Scans one text as one file. */
function scanText(text, file, ignored, findings) {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].endsWith('\r') ? lines[i].slice(0, -1) : lines[i];
    if (line === '') continue;
    for (const found of scanLine(line)) {
      if (ignored.has(fingerprint(found.value))) continue;
      findings.push({ file, line: i + 1, start: found.start, kind: found.kind, value: mask(found.value) });
    }
  }
}

// ------------------------------------------------------------------ the files

function readIgnoreList(path) {
  const ignored = new Set();
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return ignored;
  }
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    ignored.add(line.split(/\s/u)[0].toLowerCase());
  }
  return ignored;
}

function walk(root) {
  const files = [];
  const pending = [{ path: root, relative: '' }];
  while (pending.length > 0) {
    const { path, relative } = pending.pop();
    let entries;
    try {
      entries = readdirSync(path, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const name = entry.name;
      const child = relative === '' ? name : `${relative}/${name}`;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (name === '.git' || name === 'node_modules') continue;
        pending.push({ path: join(path, name), relative: child });
      } else if (entry.isFile()) {
        if (relative === '' && name === IGNORE_FILE) continue;
        if (name.endsWith('.example')) continue;
        files.push({ path: join(path, name), relative: child });
      }
    }
  }
  return files;
}

function scanFile(file, ignored, findings) {
  let buffer;
  try {
    if (statSync(file.path).size > MAX_BYTES) return;
    buffer = readFileSync(file.path);
  } catch {
    return;
  }
  if (buffer.length > MAX_BYTES) return;
  if (buffer.subarray(0, BINARY_WINDOW).includes(0)) return;
  scanText(buffer.toString('utf8'), file.relative, ignored, findings);
}

function readStandardInput() {
  const chunks = [];
  const buffer = Buffer.alloc(65536);
  for (;;) {
    let count;
    try {
      count = readSync(0, buffer, 0, buffer.length, null);
    } catch (error) {
      if (error.code === 'EAGAIN') continue;
      if (error.code === 'EOF') break;
      throw error;
    }
    if (count === 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, count)));
  }
  return Buffer.concat(chunks).toString('utf8');
}

// ------------------------------------------------------------------------ main

function parseArguments(argv) {
  const options = { json: false, stdin: false, folders: [] };
  for (const arg of argv) {
    if (arg === '--json') options.json = true;
    else if (arg === '--stdin') options.stdin = true;
    else if (arg.startsWith('-') && arg !== '-') throw new UsageError(`unknown flag: ${arg}`);
    else options.folders.push(arg);
  }
  if (options.folders.length > 1) throw new UsageError('more than one folder given');
  if (options.folders.length === 0 && !options.stdin) throw new UsageError('no folder and no --stdin');
  return options;
}

function run(argv) {
  let options;
  try {
    options = parseArguments(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    process.stderr.write(`secret-sweep: ${error.message}\n${USAGE}\n`);
    return 2;
  }

  const findings = [];
  if (options.stdin) {
    const ignored = readIgnoreList(IGNORE_FILE);
    scanText(readStandardInput(), '<stdin>', ignored, findings);
  } else {
    const folder = options.folders[0];
    let isFolder = false;
    try {
      isFolder = statSync(folder).isDirectory();
    } catch {
      isFolder = false;
    }
    if (!isFolder) {
      process.stderr.write(`secret-sweep: ${folder} is not a directory\n${USAGE}\n`);
      return 2;
    }
    const ignored = readIgnoreList(join(folder, IGNORE_FILE));
    for (const file of walk(folder)) scanFile(file, ignored, findings);
  }

  findings.sort((a, b) => {
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.line !== b.line) return a.line - b.line;
    return a.start - b.start;
  });

  if (options.json) {
    const rows = findings.map(({ file, line, kind, value }) => ({ file, line, kind, value }));
    process.stdout.write(`${JSON.stringify(rows)}\n`);
  } else if (findings.length > 0) {
    process.stdout.write(`${findings.map((f) => `${f.file}:${f.line} ${f.kind} ${f.value}`).join('\n')}\n`);
  }
  return findings.length > 0 ? 1 : 0;
}

let code;
try {
  code = run(process.argv.slice(2));
} catch {
  process.stderr.write('secret-sweep: could not finish the sweep\n');
  code = 2;
}
process.exitCode = code;
