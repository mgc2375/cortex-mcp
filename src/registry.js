import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getClient } from "./clients.js";

const exec = promisify(execFile);

export async function hexstrikeTool(name, args, timeoutMs = 900000) {
  const client = await getClient("hexstrike");
  return client.callTool({ name, arguments: args || {} }, undefined, { timeout: timeoutMs });
}

export const registry = [
  { id: "web.app.recon", kind: "hexstrike", tool: "intelligent_smart_scan", desc: "AI-driven smart recon of a target", active: true },
  { id: "web.app.dirbust", kind: "hexstrike", tool: "feroxbuster_scan", desc: "recursive directory/content discovery (url arg)", active: true },
  { id: "web.app.js", kind: "hexstrike", tool: "katana_crawl", desc: "JS-aware crawler / endpoint discovery (url arg)", active: true },
  { id: "web.app.params", kind: "hexstrike", tool: "arjun_parameter_discovery", desc: "hidden HTTP parameter discovery (url arg)", active: true },
  { id: "web.xss", kind: "hexstrike", tool: "dalfox_xss_scan", desc: "XSS scanning (url arg)", active: true },
  { id: "web.sqli", kind: "hexstrike", tool: "sqlmap_scan", desc: "SQLi scanning (url arg)", active: true },
  { id: "web.fuzz", kind: "hexstrike", tool: "ffuf_scan", desc: "fuzzing: dir, vhost, param (url arg)", active: true },
  { id: "web.tech", kind: "hexstrike", tool: "detect_technologies_ai", desc: "tech fingerprinting (target arg)" },
  { id: "web.spa_api", kind: "hexstrike", tool: "httpx_probe", desc: "live host probing + tech detect (target arg)" },
  { id: "web.bruteforce", kind: "hexstrike", tool: "hydra_attack", desc: "brute force login (target, service)", active: true },
  { id: "api.spec", kind: "upstream", upstream: "openapi", desc: "OpenAPI discovery + spec parsing against a URL" },
  { id: "api.graphql", kind: "hexstrike", tool: "graphql_scanner", desc: "GraphQL introspection/depth/authorization (endpoint arg)", active: true },
  { id: "osint.whois", kind: "builtin", tool: "whois", desc: "whois host lookup (target arg)" },
  { id: "osint.subs", kind: "hexstrike", tool: "subfinder_scan", desc: "passive subdomain enumeration (domain arg)" },
  { id: "osint.dnsenum", kind: "hexstrike", tool: "dnsenum_scan", desc: "DNS enumeration (domain arg)" },
  { id: "osint.urls", kind: "hexstrike", tool: "gau_discovery", desc: "archived/known URLs (domain arg)" },
  { id: "osint.shodan", kind: "upstream", upstream: "shodan", desc: "Shodan/VirusTotal intel (needs API keys via env)" },
  { id: "supply-chain", kind: "upstream", upstream: "osint", desc: "Supply-chain mapping & scoping: package/org enumeration, dependency mapping, exposure analysis. Full SBOM tracking needs external feeds." },
  { id: "recon.waf", kind: "hexstrike", tool: "wafw00f_scan", desc: "WAF fingerprinting (target arg)" },
  { id: "recon.net", kind: "hexstrike", tool: "nmap_scan", desc: "nmap port/service scanning" },
  { id: "recon.binary", kind: "upstream", upstream: "radare2", desc: "radare2 binary analysis" },
  { id: "chain.reason", kind: "upstream", upstream: "sequential", desc: "structured reasoning via sequential-thinking" },
  { id: "mobile.ios", kind: "upstream", upstream: "ios", desc: "ios-simulator app inspection" },
  { id: "mobile.apk", kind: "upstream", upstream: "jadx", desc: "jadx decompiled-APK static context (bridge needed)" },
  { id: "re.ghidra", kind: "upstream", upstream: "ghidra", desc: "Ghidra binary analysis — headless supported" },
  { id: "re.frida", kind: "upstream", upstream: "frida", desc: "frida dynamic instrumentation (userland + iOS sim)" },
  { id: "pkt.capture", kind: "upstream", upstream: "wiremcp", desc: "wireshark/tshark packet analysis (access_bpf needed for live capture)" },
  { id: "pkt.sip", kind: "upstream", upstream: "sipnab", desc: "SIP/RTP VoIP capture analysis (pcap files now; live capture BPF-gated)" },
  { id: "osint.intel", kind: "upstream", upstream: "osint", desc: "CloudWaddie OSINT suite (keys optional per tool)" },
  { id: "web.chrome", kind: "upstream", upstream: "chrome", desc: "Chrome DevTools live-page agent (DOM/console/network)" },
  { id: "web.browser", kind: "upstream", upstream: "playwright", desc: "Playwright browser agent for dynamic web exploitation" },
  { id: "recon.nuclei", kind: "upstream", upstream: "nuclei", desc: "Nuclei template-based vulnerability scanning (dedicated MCP)" },
  { id: "api.swagger", kind: "upstream", upstream: "swagger", desc: "OpenAPI/Swagger spec parser (swagger-mcp)" },
  { id: "code.context7", kind: "upstream", upstream: "context7", desc: "Library/framework documentation lookup (context7)" },
  { id: "kube.k8s", kind: "upstream", upstream: "kube", desc: "Kubernetes ops (kubeconfig needed)" },
  { id: "mainframe.cics", kind: "upstream", upstream: "hack3270", desc: "TN3270/CICS mainframe application testing" },
  { id: "auto.can", kind: "upstream", upstream: "peykan", desc: "CAN/OBD/UDS/J1939 — simulated vehicle on mac; real bus needs Linux box" },
  { id: "web3.audit", kind: "upstream", upstream: "solidaudit", desc: "Solidity/web3 contract audit MCP" },
  { id: "container.trivy", kind: "builtin", tool: "trivy", desc: "trivy vulnerability scan (image/filesystem/config)" },
  { id: "container.checkov", kind: "builtin", tool: "checkov", desc: "checkov IaC scan (directory arg)" },
  { id: "cloud.prowler", kind: "builtin", tool: "prowler", desc: "prowler cloud security assessment (creds needed at runtime)" },
  // suite_tools.py (~/suite/mcp/suite-tools/run.py dispatcher; kind "suite")
  { id: "osint.ctsearch", kind: "suite", tool: "ct_log_search", desc: "crt.sh CT-log search (domain)" },
  { id: "osint.ctwild", kind: "suite", tool: "parse_wildcard_sans", desc: "wildcard/internal SAN extraction from CT certs (certs arg)" },
  { id: "osint.dnsrev", kind: "suite", tool: "reverse_dns_batch", desc: "batch reverse-DNS host discovery over IP range (target=ip_start int, ip_end int)" },
  { id: "osint.spf", kind: "suite", tool: "parse_spf", desc: "SPF include/third-party sender extraction (target=txt_record)" },
  { id: "osint.dmarc", kind: "suite", tool: "parse_dmarc", desc: "DMARC policy tag extraction (target=txt_record)" },
  { id: "osint.roles", kind: "suite", tool: "detect_role_from_profile", desc: "role detection from profile/job text (target=profile_text)" },
  { id: "osint.vendors", kind: "suite", tool: "extract_vendors", desc: "security/cloud/VPN vendor mentions from text (target=text)" },
  { id: "osint.press", kind: "suite", tool: "extract_vendors_from_press", desc: "vendor/partner mentions from press-release text (target=text)" },
  { id: "osint.location", kind: "suite", tool: "detect_location_context", desc: "location context detection from text (target=text)" },
  { id: "osint.executive", kind: "suite", tool: "detect_executive_absence", desc: "executive absence context detection (target=text)" },
  { id: "osint.setech", kind: "suite", tool: "get_se_technique", desc: "social engineering technique lookup (category, technique)" },
  { id: "osint.phishing", kind: "suite", tool: "get_phishing_template", desc: "phishing template renderer (template_name, plus key field kwargs)" },
  { id: "osint.secquestions", kind: "suite", tool: "mine_security_questions", desc: "security-question answer candidates (username)" },
  { id: "osint.video", kind: "suite", tool: "harvest_video_content", desc: "video/harvest framework (url, source)" },
  { id: "brute.personal", kind: "suite", tool: "build_personal_dict", desc: "personal password dictionary (base_names, personal_vars)" },
  { id: "osint.breach", kind: "suite", tool: "dehashed_search", desc: "DeHashed breach search (query, search_type, api_key)" },
  { id: "recon.ports", kind: "suite", tool: "probe_default_ports", desc: "default/unauth port probe + banner grab (host, ports list)" },
  { id: "recon.tls", kind: "suite", tool: "tls_fingerprint", desc: "TLS cert SHA256 fingerprint (host, port)" },
  { id: "recon.favicon", kind: "suite", tool: "favicon_hash", desc: "favicon MMH3 hash for asset discovery (target=filepath)" },
  { id: "recon.hashmmh3", kind: "suite", tool: "mmh3_32", desc: "MMH3 32-bit hash (target=key, seed)" },
  { id: "recon.banner", kind: "suite", tool: "grab_banner", desc: "single-port service banner grab (host, port, timeout)" },
  { id: "code.gitsecrets", kind: "suite", tool: "scan_git_history", desc: "git history secret scan (repo_path, look_for list)" },
  { id: "code.config", kind: "suite", tool: "scan_text_for_config", desc: "config/credential pattern scan on text (target=text)" },
  { id: "code.ci", kind: "suite", tool: "scan_ci_cron", desc: "CI/CD pipeline secret scan (target=filepath)" },
  { id: "code.paste", kind: "suite", tool: "scan_paste_content", desc: "paste/gist credential pattern scan (target=text)" },
  { id: "doc.dorks", kind: "suite", tool: "build_filetype_dork", desc: "file-type Google dorks (domain, extensions list)" },
  { id: "doc.dirs", kind: "suite", tool: "brute_force_dirs", desc: "common directory path list gen (domain, depth)" },
  { id: "doc.metadata", kind: "suite", tool: "extract_doc_metadata", desc: "doc/image metadata extraction (target=filepath)" },
  { id: "doc.collect", kind: "suite", tool: "collect_documents", desc: "document collection framework (dorks list, output_dir)" },
  { id: "brute.wordlist", kind: "suite", tool: "generate_custom_wordlist", desc: "custom password wordlist builder (base_passwords, suffixes, prefixes)" },
  { id: "brute.masks", kind: "suite", tool: "generate_masks", desc: "password mask patterns (pattern_templates list)" },
];

export function pickTools(classification) {
  const classes = {
    web: ["web", "osint", "recon", "container", "code", "doc", "supply-chain"],
    api: ["api", "web", "osint", "recon", "container", "code", "doc", "supply-chain"],
    mobile: ["mobile", "re", "osint", "chain", "code", "supply-chain"],
    binary: ["re", "chain", "code"],
    network: ["recon", "pkt", "osint", "code", "supply-chain"],
    desktop: ["re", "chain", "code"],
    containers: ["container", "kube", "cloud", "code"],
    web3: ["web3", "chain", "code"],
    mainframe: ["mainframe", "chain", "code"],
    automotive: ["auto", "chain", "code"],
    other: ["osint", "recon", "web", "chain", "container", "code", "doc", "brute", "supply-chain"],
  };
  const prefixes = classes[String(classification || "other").toLowerCase()] || classes.other;
  const out = [];
  for (const pre of prefixes) {
    for (const entry of registry) {
      if ((entry.id === pre || entry.id.startsWith(pre + ".")) && !out.includes(entry)) out.push(entry);
    }
  }
  return out;
}

export const WORKFLOW_TOOLS = [
  { name: "triage_target", description: "Register a target and classify it. Creates recon/<target>/ crate (state.json, dossier.md, findings.jsonl, negatives.jsonl, chains.json). Args: {target, class:'web'|'api'|'mobile'|'binary'|'network'|'desktop'|'other', notes}", inputSchema: { type: "object", properties: { target: { type: "string" }, class: { type: "string" }, notes: { type: "string" } }, required: ["target"] } },
  { name: "understand_target", description: "Understanding pass: hexstrike analyze_target_intelligence + detect_technologies_ai, writes dossier sections. Args: {} (uses active target)", inputSchema: { type: "object", properties: { target: { type: "string" } }, additionalProperties: true } },
  { name: "propose_chains", description: "Propose attack chains via hexstrike create_attack_chain_ai + discover_attack_chains; saves chains.json. Read-style.", inputSchema: { type: "object", properties: { target: { type: "string" }, software: { type: "string" } }, additionalProperties: true } },
  { name: "request_approval", description: "Raise a pending approval gate for a tool/chain step — dash or sideband POST /approve resolves it.", inputSchema: { type: "object", properties: { chain_id: { type: "string" }, step: { type: "integer" }, tool_id: { type: "string" }, reason: { type: "string" } }, required: ["chain_id"] } },
  { name: "execute_step", description: "Execute a mapped tool for the active target. Refused in PLAN mode; requires ARM + checkpoint approval.", inputSchema: { type: "object", properties: { tool_id: { type: "string" }, args: { type: "object", additionalProperties: true } }, additionalProperties: true } },
  { name: "execute_plan", description: "Execute the proposed attack-chain steps against the active target for real (nmap/httpx/katana/nuclei/etc), recording findings and negatives. Refused in PLAN mode; requires ARM. Args: {target?, max_steps?, timeout_ms?}", inputSchema: { type: "object", properties: { target: { type: "string" }, max_steps: { type: "number" }, timeout_ms: { type: "number" } }, additionalProperties: true } },
  { name: "save_finding", description: "Record a confirmed finding into findings.jsonl. Args: {title, severity, evidence, tool}", inputSchema: { type: "object", properties: { title: { type: "string" }, severity: { type: "string" }, evidence: { type: "string" }, tool: { type: "string" } }, required: ["title", "severity"] } },
  { name: "save_negative", description: "Record a tested-and-clean result so it never gets re-tested. Args: {what, note}", inputSchema: { type: "object", properties: { what: { type: "string" }, note: { type: "string" } }, required: ["what"] } },
  { name: "ledger_report", description: "Summarize crate: mode/armed/checkpoint, dossier tail, findings, negatives, pending approval, chains.", inputSchema: { type: "object", properties: {}, additionalProperties: true } },
];

export async function cliOf(tool, args, timeoutMs) {
  try {
    const { stdout, stderr } = await exec(tool, args, { timeout: timeoutMs || 60000, maxBuffer: 20 * 1024 * 1024 });
    return { ok: true, output: (stdout + "\n" + stderr).trim().slice(0, 40000) };
  } catch (err) {
    return { ok: false, error: {
      message: String(err?.message || err).split("\n")[0],
      code: err?.code,
      tool,
    }, output: ((err.stdout ?? "") + "\n" + (err.stderr ?? "")).slice(0, 40000) };
  }
}
