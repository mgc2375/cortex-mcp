import { hexstrikeTool } from "./registry.js";

/* Chain steps come out of hexstrike as bare tool names ("nmap", "httpx", "katana").
   Map them onto the real MCP tool names + the argument key each one expects. */
const TOOL_MAP = {
  nmap: { tool: "nmap_scan", arg: "target", extra: { scan_type: "-sT -sV", ports: "1-1000" } },
  // rustscan's -p flag takes a COMMA list, not a range (nmap/masscan take ranges, rustscan does not).
  rustscan: { tool: "rustscan_fast_scan", arg: "target", extra: { ports: "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,9100" } },
  masscan: { tool: "masscan_high_speed", arg: "target", extra: { ports: "1-1000" } },
  httpx: { tool: "httpx_probe", arg: "target", extra: { tech_detect: true, status_code: true, title: true, web_server: true } },
  katana: { tool: "katana_crawl", arg: "url", extra: { depth: "3", js_crawl: true } },
  gau: { tool: "gau_discovery", arg: "domain" },
  waybackurls: { tool: "waybackurls_discovery", arg: "domain" },
  nuclei: { tool: "nuclei_scan", arg: "target", extra: { severity: "critical,high,medium" } },
  gobuster: { tool: "gobuster_scan", arg: "url", extra: { mode: "dir" } },
  dirsearch: { tool: "dirsearch_scan", arg: "url", extra: { recursive: true } },
  ffuf: { tool: "ffuf_scan", arg: "url", extra: { mode: "dir" } },
  wfuzz: { tool: "wfuzz_scan", arg: "url" },
  arjun: { tool: "arjun_parameter_discovery", arg: "url" },
  paramspider: { tool: "paramspider_discovery", arg: "domain" },
  hakrawler: { tool: "hakrawler_crawl", arg: "url" },
  sqlmap: { tool: "sqlmap_scan", arg: "url" },
  dalfox: { tool: "dalfox_xss_scan", arg: "url", extra: { pipe_mode: true } },
  xsser: { tool: "xsser_scan", arg: "url" },
  nikto: { tool: "nikto_scan", arg: "target" },
  wafw00f: { tool: "wafw00f_scan", arg: "target" },
  subfinder: { tool: "subfinder_scan", arg: "domain" },
  amass: { tool: "amass_scan", arg: "domain" },
  dnsenum: { tool: "dnsenum_scan", arg: "domain" },
  fierce: { tool: "fierce_scan", arg: "domain" },
  jaeles: { tool: "jaeles_vulnerability_scan", arg: "target" },
  graphql: { tool: "graphql_scanner", arg: "endpoint" },
  dirb: { tool: "dirb_scan", arg: "url" },
  burpsuite: { tool: "burpsuite_scan", arg: "target" },
  zap: { tool: "zap_scan", arg: "target" },
  netexec: { tool: "netexec_scan", arg: "target" },
  smbmap: { tool: "smbmap_scan", arg: "target" },
  enum4linux: { tool: "enum4linux_scan", arg: "target" },
  nbtscan: { tool: "nbtscan_netbios", arg: "target" },
  arp: { tool: "arp_scan_discovery", arg: "target" },
  hydra: { tool: "hydra_attack", arg: "target" },
  hashcat: { tool: "hashcat_crack", arg: "hash" },
  john: { tool: "john_crack", arg: "hash" },
  amass_scan: { tool: "amass_scan", arg: "domain" },
  // AutoRecon (Tib3rius) needs these to run non-interactively under hexstrike's
  // subprocess: --disable-keyboard-control avoids the termios/TTY crash, and
  // --ignore-plugin-checks skips the pre-flight abort when optional plugin tools
  // (dnsrecon/enum4linux/oracle/redis) aren't installed on this host.
  // heartbeat/timeout/port_scans/service_scans are passed explicitly because the
  // hexstrike MCP wrapper sends empty-string defaults, which would otherwise emit
  // "--heartbeat" / "--port-scans" with no value and crash argparse; port_scans/
  // service_scans="default" make hexstrike omit those flags (AutoRecon's own defaults).
  autorecon: { tool: "autorecon_scan", arg: "target", extra: { additional_args: "--ignore-plugin-checks --disable-keyboard-control", heartbeat: "60", timeout: "4", port_scans: "default", service_scans: "default", output_dir: "/tmp/autorecon" } },
  // -sS/-O/-A need root; force an unprivileged connect+version scan so it runs without sudo.
  "nmap-advanced": { tool: "nmap_advanced_scan", arg: "target", extra: { scan_type: "-sT", version_detection: true, os_detection: false, aggressive: false } },
  // hexstrike builds a broken "-A S,U,G,P" (its -A takes no arg) when shares/users/
  // groups/policy are set, so keep them off and pass a plain "-A" (all) via additional_args.
  "enum4linux-ng": { tool: "enum4linux_ng_advanced", arg: "target", extra: { additional_args: "-A", shares: false, users: false, groups: false, policy: false } },
  responder: { tool: "responder_credential_harvest", arg: "target" },
};

/* Web scanners take their endpoint in `target` but must keep scheme/port/path;
   network scanners want a bare host. */
const WEB_TARGET_TOOLS = new Set([
  "httpx_probe", "nuclei_scan", "nikto_scan", "wafw00f_scan",
  "jaeles_vulnerability_scan", "burpsuite_scan", "zap_scan",
]);

const ARG_BY_CLASS = {
  web: ["httpx_probe", "nuclei_scan", "katana_crawl", "feroxbuster_scan", "gobuster_scan", "wafw00f_scan", "nikto_scan"],
  network: ["nmap_scan", "httpx_probe", "rustscan_fast_scan", "nbtscan_netbios", "arp_scan_discovery"],
  api: ["httpx_probe", "graphql_scanner", "nuclei_scan", "arjun_parameter_discovery"],
  mobile: ["radare2_analyze", "ghidra_analysis"],
  binary: ["radare2_analyze", "ghidra_analysis", "strings_extract"],
};

const DEFAULT_PLAN = {
  web: ["httpx_probe", "wafw00f_scan", "katana_crawl", "nuclei_scan"],
  network: ["nmap_scan", "httpx_probe"],
  api: ["httpx_probe", "nuclei_scan"],
  mobile: ["radare2_analyze"],
  binary: ["strings_extract", "radare2_analyze"],
  other: ["httpx_probe"],
};

function toolArg(toolName) {
  const entry = Object.values(TOOL_MAP).find((t) => t.tool === toolName);
  return entry?.arg || "target";
}

function looksLikeDomain(s) {
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/i.test(String(s || ""));
}

function looksLikeIp(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || ""));
}

/* A target is only usable if it is an actual host — not a prose description
   like "router admin web interface". Those produced empty scans. */
export function isUsableTarget(t) {
  const s = String(t || "").trim();
  if (!s || /\s/.test(s)) return false;
  if (looksLikeIp(s)) return true;
  if (/^https?:\/\//i.test(s)) {
    let h;
    try { h = new URL(s).hostname.replace(/^\[|\]$/g, ""); } catch { return false; }
    return looksLikeDomain(h) || looksLikeIp(h) || h === "localhost";
  }
  return looksLikeDomain(s);
}

export function normalizeTarget(t) {
  let s = String(t || "").trim();
  if (!/^https?:\/\//i.test(s)) s = "http://" + s;
  return s.replace(/\/+$/, "");
}

function hostOf(t) {
  return String(t || "").replace(/^https?:\/\//i, "").replace(/\/.*$/, "").split(":")[0];
}

export function extractChainSteps(chainsPayload) {
  let raw = chainsPayload;
  if (typeof raw === "string") {
    try { raw = JSON.parse(raw); } catch { return []; }
  }
  if (!raw || typeof raw !== "object") return [];
  const steps = raw?.attack_chain?.steps || raw?.steps || [];
  if (!Array.isArray(steps)) return [];
  return steps
    .map((s) => {
      const name = String(s?.tool || "").toLowerCase().trim();
      const mapped = TOOL_MAP[name] || TOOL_MAP[name.replace(/_/g, "-")] || TOOL_MAP[name.replace(/-/g, "_")];
      if (!mapped) return null;
      const params = s?.parameters || {};
      return {
        tool: name,
        mcpTool: mapped.tool,
        arg: mapped.arg,
        extra: mapped.extra || {},
        rawParams: params,
        outcome: s?.expected_outcome || "",
        successProbability: s?.success_probability ?? null,
      };
    })
    .filter(Boolean);
}

/* Build the concrete argument payload for one chain step against one target. */
export function buildArgs(step, target) {
  const args = {};
  const host = hostOf(target);
  const url = normalizeTarget(target);
  switch (step.arg) {
    case "url":
      args.url = url;
      break;
    case "domain":
      args.domain = host;
      break;
    case "endpoint":
      args.endpoint = url;
      break;
    case "hash":
      args.hash = host;
      break;
    default:
      args.target = WEB_TARGET_TOOLS.has(step.mcpTool) ? url : host;
  }
  for (const [k, v] of Object.entries(step.extra || {})) {
    if (args[k] === undefined) args[k] = v;
  }
  /* Preserve chain-supplied tuning but never let it override the real target. */
  const rp = step.rawParams || {};
  for (const [k, v] of Object.entries(rp)) {
    if (k.startsWith("_") || k === "target" || k === "url" || k === "domain" || k === "endpoint") continue;
    if (args[k] === undefined && (typeof v === "string" || typeof v === "number" || typeof v === "boolean")) {
      args[k] = v;
    }
  }
  return args;
}

/* Textual signals that a scan surfaced something worth recording. */
const FINDING_PATTERNS = [
  { re: /\bvulnerab|(\bCVE-\d{4}-\d{4,7}\b)/i, title: "Vulnerability detected", severity: "high" },
  { re: /\bXSS\b|cross[- ]site scripting/i, title: "Cross-site scripting", severity: "high" },
  { re: /\bSQL injection\b|\bsqli\b/i, title: "SQL injection", severity: "critical" },
  { re: /\bopen redirect\b/i, title: "Open redirect", severity: "medium" },
  { re: /\bSSRF\b|server[- ]side request forgery/i, title: "Server-side request forgery", severity: "high" },
  { re: /\bexposed|anonymous access|no authentication|unauthenticated|without auth/i, title: "Unauthenticated access", severity: "high" },
  { re: /\bTLSv?1\.0\b|\bSSLv3\b|\bweak cipher\b|deprecated cipher/i, title: "Weak TLS configuration", severity: "medium" },
  { re: /\bmisconfigur|permissive|world[- ]readable|directory listing|\bindex of\b/i, title: "Misconfiguration", severity: "medium" },
  { re: /\bdefault (password|credentials)\b|\badmin:admin\b/i, title: "Default credentials", severity: "critical" },
  { re: /\b(?:api[_ -]?key|secret|password|auth[_ -]?token|access[_ -]?token|bearer)\b\s*[:=]\s*["']?[A-Za-z0-9._\-+/]{6,}|\b(?:exposed|leaked|hardcoded|plaintext)\b[^\n]{0,40}\b(?:key|token|secret|password|credential)s?\b/i, title: "Potential secret exposure", severity: "high" },
];

const NEGATIVE_PATTERNS = [
  { re: /\bNo (vulnerabilities|issues|findings) (found|detected)\b/i, what: "vulnerability scan", note: "scan completed with no findings" },
  { re: /\b0 vulnerabilities\b/i, what: "vulnerability scan", note: "0 vulnerabilities reported" },
  { re: /\ball ports (are )?(closed|filtered)\b/i, what: "port scan", note: "all scanned ports closed or filtered" },
  { re: /\bNo (hosts|domains|results) found\b/i, what: "discovery", note: "no results returned" },
  { re: /\bnot vulnerable\b|\bNo .* found\b/i, what: "scan", note: "nothing detected" },
];

function textOf(res) {
  if (!res) return "";
  if (typeof res === "string") return res;
  if (res.content) return res.content.map((c) => (typeof c === "string" ? c : (c.text ?? JSON.stringify(c)))).join("\n");
  if (res.stdout) return String(res.stdout) + "\n" + String(res.stderr || "");
  return JSON.stringify(res);
}

/* hexstrike wraps each tool result in JSON carrying {success, return_code, stderr}.
   A tool that failed to launch (bad args, missing binary) returns success:false /
   non-zero return_code but no JS exception — so execute_plan must inspect the
   payload, otherwise a broken tool is silently counted as a clean "ok" step. */
export function detectToolError(text) {
  const t = String(text || "");
  // Find the hexstrike result object even if it's embedded in surrounding text.
  let obj = null;
  try { obj = JSON.parse(t); } catch {}
  if (!obj) {
    const i = t.indexOf("{");
    const j = t.lastIndexOf("}");
    if (i >= 0 && j > i) { try { obj = JSON.parse(t.slice(i, j + 1)); } catch {} }
  }
  if (!obj || typeof obj !== "object") return null;
  const rc = obj.return_code;
  const failed = obj.success === false || (typeof rc === "number" && rc !== 0) || obj.timed_out === true;
  if (!failed) return null;
  const stderr = String(obj.stderr || obj.error || "").trim();
  const firstLine = stderr.split("\n").find((l) => l.trim()) || "";
  let message = firstLine.slice(0, 300);
  if (obj.timed_out === true && !message) message = "tool timed out";
  if (!message && typeof rc === "number") message = `exited with code ${rc}`;
  return { message: message || "tool execution failed", return_code: rc ?? null, timed_out: !!obj.timed_out };
}

/* hexstrike returns a JSON wrapper whose stdout/stderr hold the real output with
   newlines ESCAPED, so the line-anchored open-port regex never matches the raw
   wrapper. Decode to real stdout+stderr first; fall back to raw text otherwise.
   (Idempotent: already-decoded plain text is returned unchanged.) */
function decodeToolText(text) {
  const raw = String(text || "");
  let obj = null;
  try { obj = JSON.parse(raw); } catch {}
  if (!obj) {
    const i = raw.indexOf("{");
    const j = raw.lastIndexOf("}");
    if (i >= 0 && j > i) { try { obj = JSON.parse(raw.slice(i, j + 1)); } catch {} }
  }
  if (obj && typeof obj === "object" && (typeof obj.stdout === "string" || typeof obj.stderr === "string")) {
    return (String(obj.stdout || "") + "\n" + String(obj.stderr || "")).trim();
  }
  return raw;
}

/* Social platforms we can recognise in a URL and turn into a username lead. */
const SOCIAL_HOSTS = [
  { re: /(?:youtube\.com\/(?:@|channel\/|c\/|user\/)|youtu\.be\/)([A-Za-z0-9_\-.]+)/i, platform: "youtube" },
  { re: /github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)(?:\/([A-Za-z0-9._-]+))?/i, platform: "github" },
  { re: /(?:twitter|x)\.com\/([A-Za-z0-9_]{1,15})/i, platform: "twitter" },
  { re: /linkedin\.com\/(?:in|company)\/([A-Za-z0-9\-%]+)/i, platform: "linkedin" },
  { re: /instagram\.com\/([A-Za-z0-9_.]+)/i, platform: "instagram" },
  { re: /reddit\.com\/(?:user|u)\/([A-Za-z0-9_\-]+)/i, platform: "reddit" },
  { re: /keybase\.io\/([A-Za-z0-9_]+)/i, platform: "keybase" },
  { re: /tiktok\.com\/@([A-Za-z0-9_.]+)/i, platform: "tiktok" },
  { re: /t\.me\/([A-Za-z0-9_]{4,32})/i, platform: "telegram" },
  { re: /steamcommunity\.com\/id\/([A-Za-z0-9_\-]+)/i, platform: "steam" },
];
const ASSET_EXT = /\.(png|jpe?g|gif|svg|webp|css|js|mjs|json|xml|woff2?|ttf|ico|map|txt|md|pdf)($|\?)/i;

/* Extract typed signals (leads) from raw tool output — the raw material the
   inference engine reasons over. High-precision regex only; deduped and bounded.
   Scope decisions (which to actually pursue) are made by the dispatcher, not here. */
export function extractSignals(raw) {
  const t = decodeToolText(raw).slice(0, 300000);
  const out = [];
  const seen = new Set();
  const add = (type, value, meta) => {
    const v = String(value || "").trim().replace(/[.,);\]]+$/, "");
    if (!v) return;
    const k = type + ":" + v.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    out.push(meta ? { type, value: v, ...meta } : { type, value: v });
  };
  for (const m of t.matchAll(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g)) add("email", m[0].toLowerCase());
  const urls = [];
  for (const m of t.matchAll(/https?:\/\/[^\s"'<>)\]}]+/g)) urls.push(m[0].replace(/[.,);\]]+$/, ""));
  for (const u of urls) {
    let social = false;
    for (const s of SOCIAL_HOSTS) {
      const mm = u.match(s.re);
      if (mm) { add("social", u, { platform: s.platform, handle: mm[1] || "" }); if (mm[1]) add("username", mm[1], { platform: s.platform }); social = true; }
    }
    if (social) continue;
    if (/\.s3[.\-]|s3\.amazonaws\.com|\.blob\.core\.windows\.net|storage\.googleapis\.com|\.r2\.dev/i.test(u)) { add("bucket", u); continue; }
    if (/swagger|openapi|\/graphql\b|api-docs|\/v\d\/|\.wsdl/i.test(u)) add("api_spec", u);
    if (ASSET_EXT.test(u)) continue;
    add("url", u);
  }
  for (const m of t.matchAll(/\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi)) {
    const d = m[1].toLowerCase();
    if (ASSET_EXT.test(d) || /\d+\.\d+\.\d+\.\d+/.test(d)) continue;
    add("domain", d);
  }
  for (const m of t.matchAll(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g)) {
    if ([m[1], m[2], m[3], m[4]].every((o) => +o <= 255)) add("ip", `${m[1]}.${m[2]}.${m[3]}.${m[4]}`);
  }
  for (const m of t.matchAll(/CVE-\d{4}-\d{4,7}/gi)) add("cve", m[0].toUpperCase());
  for (const m of t.matchAll(/\b([A-Za-z][A-Za-z0-9+.\-]{1,24})\/(\d+\.\d[\w.\-]*)/g)) add("tech", `${m[1]}/${m[2]}`, { product: m[1], version: m[2] });
  for (const m of t.matchAll(/\b0x[a-fA-F0-9]{40}\b/g)) add("eth", m[0]);
  for (const m of t.matchAll(/\bAS\d{2,6}\b/g)) add("asn", m[0]);
  if (/AKIA[0-9A-Z]{16}/.test(t)) add("secret", "aws_access_key");
  if (/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/.test(t)) add("secret", "private_key");
  if (/xox[baprs]-[0-9A-Za-z\-]{10,}/.test(t)) add("secret", "slack_token");
  if (/gh[pousr]_[A-Za-z0-9]{36}/.test(t)) add("secret", "github_token");
  return out.slice(0, 150);
}

export function classifyOutput(text, tool) {
  const t = decodeToolText(text);
  const findings = [];
  for (const p of FINDING_PATTERNS) {
    if (p.re.test(t)) findings.push({ title: p.title, severity: p.severity, evidence: snippet(t, p.re) });
  }
  let negative = null;
  for (const p of NEGATIVE_PATTERNS) {
    if (p.re.test(t)) { negative = { what: p.what, note: p.note, tool }; break; }
  }
  const openPorts = [...t.matchAll(/^(\d+)\/tcp\s+open\s+(\S+)?/gm)].map((m) => ({
    port: Number(m[1]), service: m[2] || "unknown",
  }));
  return { findings, negative, openPorts, signals: extractSignals(t) };
}

function snippet(text, re) {
  const m = String(text).match(re);
  if (!m) return "";
  const i = m.index;
  return String(text).slice(Math.max(0, i - 120), i + 220).trim();
}

/* Fallback plan when hexstrike gave us nothing usable. */
export function defaultPlan(classification) {
  const cls = String(classification || "other").toLowerCase();
  const tools = DEFAULT_PLAN[cls] || DEFAULT_PLAN.other;
  return tools.map((mcpTool) => {
    const arg = toolArg(mcpTool);
    return { tool: mcpTool, mcpTool, arg, extra: {}, rawParams: {}, outcome: `run ${mcpTool}`, successProbability: null };
  });
}

export function planFor(classification) {
  const cls = String(classification || "other").toLowerCase();
  return ARG_BY_CLASS[cls] || ARG_BY_CLASS.other || ARG_BY_CLASS.web;
}

/* Relentless escalation arsenal per class, ordered cheap-recon -> deep/aggressive.
   The hunt walks this when a round finds nothing, skipping tools already tried. */
const ESCALATION = {
  web: ["httpx", "wafw00f", "nuclei", "katana", "nikto", "gobuster", "arjun", "ffuf", "dalfox", "sqlmap", "graphql", "dirsearch", "hakrawler", "paramspider", "gau", "waybackurls", "wfuzz", "jaeles"],
  api: ["httpx", "nuclei", "arjun", "graphql", "ffuf", "katana", "paramspider", "gau", "nikto", "jaeles"],
  network: ["nmap", "rustscan", "httpx", "nmap-advanced", "autorecon", "nuclei", "enum4linux-ng", "nbtscan", "smbmap", "netexec", "fierce"],
  other: ["httpx", "nmap", "nuclei", "wafw00f", "katana", "subfinder", "gau", "dnsenum", "arjun", "autorecon"],
};

/* Returns ordered steps (via TOOL_MAP) for the given class, excluding any whose
   real mcp tool is already in `triedMcpTools`. Used to keep escalating until a hit. */
export function escalationLadder(classification, triedMcpTools) {
  const cls = String(classification || "other").toLowerCase();
  const names = ESCALATION[cls] || ESCALATION.other;
  const tried = new Set(triedMcpTools || []);
  const out = [];
  for (const name of names) {
    const mapped = TOOL_MAP[name];
    if (!mapped || tried.has(mapped.tool)) continue;
    tried.add(mapped.tool);
    out.push({ tool: name, mcpTool: mapped.tool, arg: mapped.arg, extra: mapped.extra || {}, rawParams: {}, outcome: `escalate: ${name}`, successProbability: null });
  }
  return out;
}

export { hexstrikeTool, toolArg };
