#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
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
import { UPSTREAMS, getClient, listServerTools, spawnDetached } from "./clients.js";
import { verbs } from "./workflow.js";
import { registry, pickTools } from "./registry.js";
import { callEntry, callUpstreamTool } from "./entry.js";
import {
  lastState, readState, writeState, readJsonl, readPending, writePending,
  appendEvent, readEvents, ensureCrate, activeTarget, readDossier, cratePath,
} from "./crate.js";
import { WORKFLOW_TOOLS } from "./registry.js";
import { setSink } from "./bus.js";

// Load API keys from config.json into the environment so upstreams that read
// process.env (e.g. osint-mcp's EMAILOSINT_API_KEY / direct-env keys) pick them up.
try {
  const _cfg = JSON.parse(fs.readFileSync(path.join(process.cwd(), "config.json"), "utf8"));
  for (const [k, v] of Object.entries(_cfg)) if (typeof v === "string" && v && !process.env[k]) process.env[k] = v;
} catch {}

const SIDEBAND_HOST = "127.0.0.1";
const SIDEBAND_PORT = 5630;
const SUBS = new Set();
const BUSES = new Set();

function broadcast(line) {
  for (const f of SUBS) {
    try { f(line); } catch {}
  }
}

function emit(event) {
  broadcast(JSON.stringify(event));
}

// Let workflow.js stream live events (per-tool start/output/heartbeat/escalation)
// straight to SSE subscribers mid-execution, instead of only after a verb returns.
setSink(broadcast);

async function readBody(req) {
  let buf = "";
  for await (const chunk of req) buf += chunk;
  try { return JSON.parse(buf); } catch { return {}; }
}

const server = new Server({ name: "cortex", version: "0.1.0" }, { capabilities: { tools: {} } });

const MCP_TOOLS = WORKFLOW_TOOLS.filter((t) => t.name !== "list_tools").concat([
  {
    name: "list_tools",
    description: "List cortex registry entries and upstream inventory. Args: {class:'web'|'api'|'mobile'|'binary'|'network', raw:false}",
    inputSchema: {
      type: "object",
      properties: { class: { type: "string" }, raw: { type: "boolean" } },
      additionalProperties: true,
    },
  },
  {
    name: "call_tool",
    description: "Run a registry entry by id with args {tool_id, target, args} — gated by PLAN mode (read-style ok in plan unless refused).",
    inputSchema: {
      type: "object",
      properties: { tool_id: { type: "string" }, target: { type: "string" }, args: { type: "object", additionalProperties: true } },
      required: ["tool_id"],
      additionalProperties: true,
    },
  },
  {
    name: "list_upstreams",
    description: "Enumerate available upstream MCP servers and their tool inventories (lazily boots each).",
    inputSchema: { type: "object", properties: { server: { type: "string" } }, additionalProperties: true },
  },
]);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MCP_TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    let out;
    if (name === "list_tools") {
      const pick = args?.class ? pickTools(args.class) : registry;
      out = {
        mode: lastState()?.mode || "plan",
        class: args?.class || null,
        registry: pick.map((t) => ({ id: t.id, kind: t.kind, upstream: t.upstream, desc: t.desc })),
        upstreams: Object.entries(UPSTREAMS).map(([k, v]) => ({ name: k, desc: v.desc })),
      };
    } else if (name === "call_tool") {
      const target = args?.target || activeTarget();
      const refusal = gateCallTool(args.tool_id, target);
      if (refusal) {
        out = refusal;
      } else {
        const result = await callEntry(args.tool_id, target, args?.args || {});
        if (target) appendEvent(target, args.tool_id, { summary: (result.output || result.error || "").toString().slice(0, 200) });
        out = result;
      }
    } else if (name === "list_upstreams") {
      const names = args?.server ? [args.server] : Object.keys(UPSTREAMS);
      out = {};
      for (const key of names) {
        try {
          const tools = await listServerTools(key);
          out[key] = { count: tools.length, tools: tools.slice(0, 200) };
        } catch (err) {
          out[key] = { error: String(err?.message || err).split("\n")[0] };
        }
      }
    } else if (verbs[name]) {
      out = await verbs[name](args || {});
      const target = lastState()?.target;
      if (target) {
        const ev = appendEvent(target, name, { summary: JSON.stringify(out).slice(0, 200) });
        emit(JSON.parse(ev));
      }
    } else {
      out = { error: `unknown tool: ${name}`, known: MCP_TOOLS.map((t) => t.name) };
    }
    return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
  } catch (err) {
    return { content: [{ type: "text", text: `cortex error: ${err?.stack || err}` }], isError: true };
  }
});

/* Gate active/offensive registry tools behind FULL+ARM (+paranoid approval),
   the same interlock as /execute and execute_plan. Passive/read-style entries
   (no `active` flag) run in plan mode so recon stays usable. */
function gateCallTool(toolId, target) {
  const entry = registry.find((e) => e.id === toolId);
  if (!entry || !entry.active) return null;
  const st = target ? readState(target) : null;
  if (!st || st.mode !== "full" || !st.armed)
    return { refused: true, reason: "plan-mode", detail: "PLAN mode: active tool refused. Switch to FULL mode and ARM to continue." };
  const pend = readPending(target);
  if (st.checkpoint === "paranoid" && (!pend || pend.decision !== "approved"))
    return { refused: true, reason: "pending-approval", pending: pend };
  if (pend && pend.decision === "approved") writePending(target, null);
  return null;
}

const httpServer = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:5321");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
  const u = new URL(req.url, "http://x");
  // Allow target management even when no target is active yet
  if (u.pathname === "/target") {
    const body = await readBody(req);
    if (body && body.set) {
      const dir = cratePath(body.set);
      fs.mkdirSync(dir, { recursive: true });
      const statePath = path.join(dir, "state.json");
      let st;
      try {
        st = JSON.parse(fs.readFileSync(statePath, "utf8"));
        st.class = body.class || st.class || null;
        st.updated_at = new Date().toISOString();
      } catch {
        st = { target: body.set, phase: "idle", class: body.class || null, mode: "plan", checkpoint: "normal", armed: false, findings_count: 0, negatives_count: 0, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
      }
      fs.writeFileSync(statePath, JSON.stringify(st, null, 2));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, target: body.set, previous: null }));
    } else if (body && body.clear) {
      const prev = activeTarget();
      if (!prev) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, target: null, previous: null }));
        return;
      }
      const dir = cratePath(prev);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, target: null, previous: prev }));
    } else {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "usage: {set:'targetname'} or {clear:true}" }));
    }
    return;
  }
  let target = null, state = null;
  try {
    target = activeTarget();
    state = target ? readState(target) : null;
    if (u.pathname === "/state") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ state, pending: target ? readPending(target) : null, dossier: target ? readDossier(target).slice(-8000) : "" }));
    } else if (u.pathname === "/findings" || u.pathname === "/negatives") {
      const which = u.pathname === "/findings" ? "findings.jsonl" : "negatives.jsonl";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(target ? readJsonl(target, which, 200) : []));
    } else if (u.pathname === "/events-history") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(target ? readEvents(target, 200) : []));
    } else if (u.pathname === "/events" && req.headers.accept?.includes("text/event-stream")) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      res.write("retry: 2000\n\n");
      const push = (line) => res.write(`data: ${line}\n\n`);
      SUBS.add(push);
      req.on("close", () => SUBS.delete(push));
    } else if (req.method === "POST" && u.pathname === "/call_tool") {
      const body = await readBody(req);
      const toolId = body?.tool_id;
      const target = body?.target || activeTarget();
      if (toolId === "list_tools") {
        const pick = body?.args?.class ? pickTools(body.args.class) : registry;
        const result = {
          mode: lastState()?.mode || "plan",
          class: body?.args?.class || null,
          registry: pick.map((t) => ({ id: t.id, kind: t.kind, upstream: t.upstream, desc: t.desc })),
          upstreams: Object.entries(UPSTREAMS).map(([k, v]) => ({ name: k, desc: v.desc })),
        };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(result));
        return;
      }
      if (verbs[toolId]) {
        const result = await verbs[toolId](body?.args || {});
        const tgt = body?.target || lastState()?.target || activeTarget();
        if (tgt) {
          const ev = appendEvent(tgt, toolId, { summary: JSON.stringify(result).slice(0, 200) });
          try { emit(JSON.parse(ev)); } catch {}
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(result));
        return;
      }
      const refusal = gateCallTool(toolId, target);
      if (refusal) {
        res.writeHead(refusal.reason === "pending-approval" ? 428 : 403, { "content-type": "application/json" });
        res.end(JSON.stringify(refusal));
        return;
      }
      const result = await callEntry(toolId, target, body?.args || {});
      if (target) {
        const ev = appendEvent(target, toolId, { summary: String(result?.output || result?.error || "").slice(0, 200) });
        try { emit(JSON.parse(ev)); } catch {}
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    } else if (req.method === "POST" && u.pathname === "/call_upstream") {
      // Call ONE named tool on any upstream MCP (the full surface, not just first-tool).
      // No active target required — OSINT/intel lookups run standalone.
      const body = await readBody(req);
      const result = await callUpstreamTool(body?.server, body?.tool, body?.args || {});
      const tgt = activeTarget();
      if (tgt) { const ev = appendEvent(tgt, `${body?.server}:${body?.tool}`, { summary: String(result?.output || result?.error || "").slice(0, 200) }); try { emit(JSON.parse(ev)); } catch {} }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    } else if (req.method === "POST" && !target) {
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "no active target" }));
    } else if (req.method === "POST" && u.pathname === "/approve") {
      const body = await readBody(req);
      const pend = readPending(target);
      if (!pend) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "nothing pending" }));
      } else {
        pend.decision = body.decision || "approved";
        pend.decided_at = new Date().toISOString();
        const final = { ...pend };
        if (pend.decision === "approved" && state?.checkpoint !== "paranoid") writePending(target, null);
        else writePending(target, final);
        const ev = appendEvent(target, "approval", { id: pend.id, decision: pend.decision });
        try { emit(JSON.parse(ev)); } catch {}
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, pending: final }));
      }
    } else if (req.method === "POST" && u.pathname === "/mode") {
      const body = await readBody(req);
      const m = body.mode === "full" ? "full" : "plan";
      writeState(target, { mode: m });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, mode: m }));
    } else if (req.method === "POST" && u.pathname === "/arm") {
      const body = await readBody(req);
      writeState(target, { armed: !!body.armed, armed_at: body.armed ? new Date().toISOString() : null });
      const ev = appendEvent(target, body.armed ? "armed" : "disarmed", {});
      try { emit(JSON.parse(ev)); } catch {}
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, armed: !!body.armed }));
    } else if (req.method === "POST" && u.pathname === "/checkpoint") {
      const body = await readBody(req);
      const c = ["paranoid", "normal", "yolo"].includes(body.checkpoint) ? body.checkpoint : "normal";
      writeState(target, { checkpoint: c });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, checkpoint: c }));
    } else if (req.method === "POST" && u.pathname === "/execute") {
      const body = await readBody(req);
      ensureCrate(target);
      const st = readState(target);
      if (st.mode !== "full" || !st.armed) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ refused: true, reason: "plan-mode" }));
        return;
      }
      const pend = readPending(target);
      if (st.checkpoint === "paranoid" && (!pend || pend.decision !== "approved")) {
        res.writeHead(428, { "content-type": "application/json" });
        res.end(JSON.stringify({ refused: true, reason: "pending-approval", pending: pend }));
        return;
      }
      if (pend && pend.decision === "approved") writePending(target, null);
      appendEvent(target, "exec", { tool_id: body.tool_id });
      const result = await callEntry(body.tool_id, target, body.args || { target });
      appendEvent(target, "exec_done", { tool_id: body.tool_id, ok: !!result?.ok });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    } else {
      res.writeHead(404);
      res.end();
    }
  } catch (err) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: String(err?.stack || err) }));
  }
});

console.error("[cortex] booting stdio MCP");
spawnDetached([`${process.env.HOME}/suite/mcps/pyenv2/bin/peykan`, "simulate"]);
const transport = new StdioServerTransport();
server.connect(transport).catch(() => {});
httpServer.on("error", () => {
  console.error("[cortex] sideband port busy — skipping (another cortex owns 5630)");
});
httpServer.listen(SIDEBAND_PORT, SIDEBAND_HOST, () => {
  console.error(`[cortex] sideband on http://${SIDEBAND_HOST}:${SIDEBAND_PORT}`);
});
