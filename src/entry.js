import { cliOf, hexstrikeTool } from "./registry.js";
import { getClient } from "./clients.js";
import { registry } from "./registry.js";
import { detectToolError } from "./execplan.js";
import fs from "node:fs";

const HOME = process.env.HOME;
// pyenv2 was an anaconda-based venv that no longer exists; the hexstrike venv has
// python + requests and is always present, so suite_tools.py runs there.
const SUITE_PY = `${HOME}/hexstrike-ai/hexstrike_env/bin/python`;
const SUITE_RUN = `${HOME}/suite/mcp/suite-tools/run.py`;

function normText(res) {
  if (typeof res === "string") return res;
  if (res?.content) return res.content.map((c) => typeof c === "string" ? c : (c.text ?? JSON.stringify(c))).join("\n");
  return JSON.stringify(res, null, 2);
}

async function upstreamAuto(name, argsLike) {
  const client = await getClient(name.upstream);
  const listing = await client.listTools();
  const list = listing.tools || [];
  const hint = Object.entries(argsLike)
    .map(([k, v]) => [k, v && typeof v === "string" ? v.slice(0, 80) : v]);
  const first = list[0];
  if (!first) return { ok: false, error: `upstream ${name.upstream} has no tools`, listing: [] };
  return {
    ok: true,
    upstream: name.upstream,
    tool: first.name,
    description: first.name ? first.description : null,
    listing: list.slice(0, 40).map((t) => t.name),
    result: normText(await client.callTool({ name: first.name, arguments: reflect(argsLike, first.inputSchema) })),
  };
}

function reflect(argsLike, schema) {
  const out = {};
  const props = schema?.properties || {};
  for (const key of Object.keys(props)) {
    if (argsLike[key] !== undefined) out[key] = argsLike[key];
  }
  if (!Object.keys(out).length) out.url = argsLike.target || argsLike.domain || argsLike.endpoint || argsLike.query;
  return out;
}

/* Map provided args onto a tool's schema: exact-key match first, then fill any
   required prop (or the sole prop) from a generic value the caller supplied. Lets
   the inference engine call any upstream tool with either {email:x} or {value:x}. */
function reflectArgs(args, schema) {
  const props = schema?.properties || {};
  const req = Array.isArray(schema?.required) ? schema.required : [];
  const out = {};
  for (const key of Object.keys(props)) if (args[key] !== undefined) out[key] = args[key];
  const generic = args.value ?? args.target ?? args.query ?? args.domain ?? args.url ?? args.email ?? args.username ?? args.ip;
  for (const key of req) if (out[key] === undefined && generic !== undefined) out[key] = generic;
  if (!Object.keys(out).length && generic !== undefined) {
    const first = Object.keys(props)[0];
    if (first) out[first] = generic;
  }
  return out;
}

/* Call ONE specific tool on an upstream MCP by name (not just the server's first
   tool, which is all upstreamAuto can do). This is what unlocks the full upstream
   surface — all 57 osint tools, etc. — for the inference engine to dispatch. */
export async function callUpstreamTool(server, toolName, args) {
  try {
    const client = await getClient(server);
    const listing = await client.listTools();
    const list = listing.tools || [];
    const tool = list.find((t) => t.name === toolName);
    if (!tool) return { ok: false, upstream: server, error: `no tool "${toolName}" on ${server}`, available: list.map((t) => t.name).slice(0, 100) };
    const res = await client.callTool({ name: toolName, arguments: reflectArgs(args || {}, tool.inputSchema) });
    const text = normText(res);
    const toolErr = detectToolError(text);
    if (toolErr) return { ok: false, upstream: server, tool: toolName, error: toolErr.message, output: text.slice(0, 50000) };
    return { ok: true, upstream: server, tool: toolName, output: text.slice(0, 50000) };
  } catch (e) {
    return { ok: false, upstream: server, tool: toolName, error: String(e?.message || e).split("\n")[0] };
  }
}

export async function callEntry(entryId, target, args) {
  const entry = registry.find((e) => e.id === entryId);
  if (!entry) return { ok: false, error: `unknown registry id: ${entryId}`, known: registry.map((e) => e.id) };

  const input = { target, ...args };

  if (entry.kind === "hexstrike") {
    const params = { ...input };
    if (HX.has(entry.tool)) params.url = params.url || params.target;
    else if (entry.tool === "graphql_scanner") params.endpoint = params.endpoint || params.target;
    else if (entry.id.startsWith("osint")) params.domain = params.domain || params.target;
    const res = await hexstrikeTool(entry.tool, params);
    const text = normText(res);
    const toolErr = detectToolError(text);
    if (toolErr) {
      return {
        ok: false,
        tool: entry.tool,
        error: toolErr.message,
        timed_out: toolErr.timed_out,
        return_code: toolErr.return_code,
        output: text.slice(0, 50000),
      };
    }
    return { ok: true, tool: entry.tool, output: text.slice(0, 50000) };
  }

  if (entry.kind === "suite") {
    return cliOf(SUITE_PY, [SUITE_RUN, entry.tool, JSON.stringify(input)], 120000);
  }

  if (entry.kind === "upstream") {
    return upstreamAuto(entry, input);
  }

  if (entry.kind === "builtin") {
    if (entry.tool === "whois") return cliOf("whois", [input.whois_host || input.target]);
    if (entry.tool === "trivy") {
      const mode = input.mode || "filesystem";
      const tgt = input.target || input.image || ".";
      return cliOf("/opt/homebrew/bin/trivy", [mode, tgt], 300000);
    }
    if (entry.tool === "checkov") return cliOf(`${HOME}/.local/bin/checkov`, ["-d", input.dir || input.target]);
    if (entry.tool === "prowler") return cliOf(`${HOME}/.local/bin/prowler`, input.prov ? [input.prov] : (input.args || []), 600000);
    return cliOf(entry.tool, [input.target]);
  }

  return { ok: false, error: `kind ${entry.kind} unimplemented` };
}

const HX = new Set(["feroxbuster_scan", "katana_crawl", "arjun_parameter_discovery", "dalfox_xss_scan", "sqlmap_scan", "ffuf_scan"]);
