import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const HOME = os.homedir();

export function cratePath(target) {
  const base = path.join(HOME, "recon");
  let safe = String(target ?? "").replace(/[^\w.-]+/g, "_").replace(/^\.+$/, "").slice(0, 100);
  if (!safe) safe = "_default";                 // '', null, undefined, '.', '..', '...' -> _default
  const dir = path.join(base, safe);
  if (dir !== base && !dir.startsWith(base + path.sep)) {
    throw new Error(`invalid target path: ${JSON.stringify(target)}`);
  }
  return dir;
}

const STATE_FILE = "state.json";
const FINDINGS = "findings.jsonl";
const NEGATIVES = "negatives.jsonl";
const CHAINS = "chains.json";
const DOSSIER = "dossier.md";
const EVENTS = "events.log";
const PENDING = "pending_approval.json";

const DEFAULT_STATE = {
  target: null,
  phase: "idle",
  class: null,
  mode: "plan",
  checkpoint: "normal",
  armed: false,
  findings_count: 0,
  negatives_count: 0,
  created_at: null,
  updated_at: null,
};

export function ensureCrate(target) {
  const dir = cratePath(target);
  fs.mkdirSync(dir, { recursive: true });
  for (const f of [FINDINGS, NEGATIVES, EVENTS]) {
    const p = path.join(dir, f);
    if (!fs.existsSync(p)) fs.writeFileSync(p, "");
  }
  const sp = path.join(dir, STATE_FILE);
  if (!fs.existsSync(sp)) {
    writeState(target, { ...DEFAULT_STATE, created_at: new Date().toISOString() });
    if (!fs.existsSync(path.join(dir, DOSSIER))) {
      fs.writeFileSync(path.join(dir, DOSSIER), `# Dossier ${target}\n\nTarget registered.\n`);
    }
  }
  return dir;
}

export function readState(target) {
  const sp = path.join(cratePath(target), STATE_FILE);
  try {
    return JSON.parse(fs.readFileSync(sp, "utf8"));
  } catch {
    return { ...DEFAULT_STATE, target };
  }
}

export function writeState(target, patch) {
  const dir = cratePath(target);
  fs.mkdirSync(dir, { recursive: true });
  const st = { ...DEFAULT_STATE, ...readState(target), ...patch, target, updated_at: new Date().toISOString() };
  fs.writeFileSync(path.join(dir, STATE_FILE), JSON.stringify(st, null, 2));
  return st;
}

export function lastState() {
  const root = path.join(HOME, "recon");
  if (!fs.existsSync(root)) return null;
  const dirs = fs.readdirSync(root).filter((d) => fs.existsSync(path.join(root, d, STATE_FILE)));
  if (!dirs.length) return null;
  const parsed = dirs
    .map((d) => {
      try {
        return { d, st: JSON.parse(fs.readFileSync(path.join(root, d, STATE_FILE), "utf8")) };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  if (!parsed.length) return null;
  const pick = parsed.sort((a, b) => (b.st.updated_at || "").localeCompare(a.st.updated_at || ""))[0];
  return pick.st;
}

export function activeTarget() {
  return lastState()?.target || null;
}

export function appendJson(target, file, obj) {
  const dir = cratePath(target);
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(path.join(dir, file), JSON.stringify({ ts: new Date().toISOString(), ...obj }) + "\n");
  const key = file === FINDINGS ? "findings_count" : "negatives_count";
  const st = readState(target);
  writeState(target, { [key]: (st[key] || 0) + 1 });
  return readState(target)[key];
}

export function readJsonl(target, file, limit = 100) {
  const p = path.join(cratePath(target), file);
  try {
    const lines = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-limit).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((r) => r !== null);
  } catch {
    return [];
  }
}

export function writeChains(target, chains) {
  fs.mkdirSync(cratePath(target), { recursive: true });
  fs.writeFileSync(path.join(cratePath(target), CHAINS), JSON.stringify(chains, null, 2));
}

export function readChains(target) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cratePath(target), CHAINS), "utf8"));
  } catch {
    return null;
  }
}

export function appendDossier(target, section, body) {
  const dir = cratePath(target);
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(path.join(dir, DOSSIER), `\n## ${section}\n${String(body).replace(/\0/g, "").trim()}\n`);
}

export function readDossier(target) {
  try {
    return fs.readFileSync(path.join(cratePath(target), DOSSIER), "utf8").slice(-20000);
  } catch {
    return "";
  }
}

export function appendEvent(target, kind, data) {
  const dir = cratePath(target);
  fs.mkdirSync(dir, { recursive: true });
  const line = JSON.stringify({ ts: new Date().toISOString(), kind, target, ...data });
  fs.appendFileSync(path.join(dir, EVENTS), line + "\n");
  return line;
}

export function readEvents(target, limit = 60) {
  const p = path.join(cratePath(target), EVENTS);
  try {
    const lines = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-limit).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((r) => r !== null);
  } catch {
    return [];
  }
}

export function readPending(target) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cratePath(target), PENDING), "utf8"));
  } catch {
    return null;
  }
}

export function writePending(target, obj) {
  const p = path.join(cratePath(target), PENDING);
  if (!obj) {
    try { fs.unlinkSync(p); } catch {}
    return;
  }
  fs.mkdirSync(cratePath(target), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
}
