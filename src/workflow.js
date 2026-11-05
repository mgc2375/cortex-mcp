import {
  ensureCrate, readState, writeState, readPending, writePending,
  appendJson, readJsonl, writeChains, readChains, appendEvent, appendDossier, cratePath, activeTarget, readDossier,
} from "./crate.js";
import { hexstrikeTool, cliOf } from "./registry.js";
import { callEntry } from "./entry.js";
import { extractChainSteps, buildArgs, classifyOutput, detectToolError, defaultPlan, escalationLadder, isUsableTarget, normalizeTarget } from "./execplan.js";
import { emitLine } from "./bus.js";

/* Append an event to the crate log AND push it live to SSE subscribers, so the
   dashboard sees per-tool activity as it happens instead of only after the verb. */
function stream(target, kind, data) {
  const line = appendEvent(target, kind, data || {});
  emitLine(line);
  return line;
}

/* Persist + live-stream the typed leads a tool surfaced, so the inference engine
   (and the console) can see emails/usernames/hosts/CVEs/etc. as they're found. */
function recordSignals(target, toolId, signals, round) {
  if (!signals || !signals.length) return;
  for (const s of signals) appendJson(target, "signals.jsonl", { ...s, tool: toolId });
  stream(target, "signals", { tool: toolId, round, count: signals.length, items: signals.slice(0, 40) });
}

/* The non-hexstrike arsenal the hunt also sweeps, by class: OSINT/recon suite tools,
   builtins (whois), and the osint MCP upstream — so the hunt uses ALL of cortex. These
   are registry IDs executed via callEntry (which dispatches to suite/builtin/upstream). */
const CORTEX_SWEEP = {
  web: ["osint.whois", "osint.ctsearch", "recon.tls", "osint.intel", "supply-chain"],
  api: ["osint.whois", "osint.intel", "supply-chain"],
  network: ["osint.whois", "recon.tls", "recon.ports", "osint.intel", "supply-chain"],
  other: ["osint.whois", "osint.ctsearch", "recon.tls", "recon.ports", "osint.intel", "supply-chain"],
};

/* Run one registry entry via callEntry (any kind: hexstrike/suite/builtin/upstream),
   streaming the same live events as a hexstrike tool and recording findings/negatives. */
async function runRegistryTool(target, id, round, perToolTimeout) {
  const start = Date.now();
  stream(target, "tool_start", { tool: id, chain_tool: id, args: { target }, round });
  const hb = setInterval(() => stream(target, "heartbeat", { tool: id, round, elapsed_ms: Date.now() - start }), 4000);
  let res = null, error = null;
  try {
    res = await Promise.race([
      callEntry(id, target, { target }),
      new Promise((_, r) => setTimeout(() => r(new Error("tool timeout")), perToolTimeout)),
    ]);
  } catch (e) {
    error = String(e?.message || e).split("\n")[0];
  } finally {
    clearInterval(hb);
  }
  if (!error && res && res.ok === false) error = (res.error && (res.error.message || res.error)) || "tool failed";
  const text = error ? "" : String(res?.output ?? "");
  const classified = classifyOutput(text, id);
  const ms = Date.now() - start;
  const findings = error ? [] : classified.findings;
  const record = { tool: id, chain_tool: id, args: { target }, round, ok: !error, error, findings, open_ports: error ? [] : classified.openPorts, negative: error ? null : classified.negative, signals: error ? [] : classified.signals, output_tail: text.slice(-1200), ms };
  stream(target, "tool_output", { tool: id, round, ok: !error, tail: (error ? error : text).slice(-600), ms });
  if (error) {
    appendJson(target, "negatives.jsonl", { what: `${id} failed`, note: error, tool: id });
    stream(target, "exec_error", { id, error, round });
  }
  for (const f of findings) {
    appendJson(target, "findings.jsonl", { title: f.title, severity: f.severity, evidence: f.evidence, tool: id });
    stream(target, "finding", { title: f.title, severity: f.severity, tool: id, round });
  }
  if (record.negative && !findings.length) {
    appendJson(target, "negatives.jsonl", { what: record.negative.what, note: record.negative.note, tool: id });
  }
  recordSignals(target, id, record.signals, round);
  stream(target, "tool_done", { id, ok: record.ok, findings: findings.length, signals: record.signals.length, ms, round });
  appendDossier(target, `Cortex · ${id}`, text.slice(-2000));
  return record;
}

function act() {
  const target = activeTarget();
  if (!target) throw new Error("no active target — call triage_target first");
  return target;
}

export const verbs = {
  triage_target: async (args) => {
    ensureCrate(args.target);
    writeState(args.target, { class: args.class || "other", phase: "triaged", notes: args.notes || "" });
    if (args.class) appendDossier(args.target, "Triage", `Class: ${args.class}\nNotes: ${args.notes || "-"}`);
    appendEvent(args.target, "triaged", { class: args.class });
    return { ok: true, crate: cratePath(args.target), class: args.class || null };
  },
  understand_target: async (args) => {
    const target = args?.target || act();
    ensureCrate(target);
    const intel = await hexstrikeTool("analyze_target_intelligence", { target });
    const text = pick(intel);
    const tech = await hexstrikeTool("detect_technologies_ai", { target });
    const techText = pick(tech);
    appendDossier(target, "Understanding", `Intel:\n${text}\nTech:\n${techText}`);
    stream(target, "reasoning", { phase: "understand", text: (`Intel: ${text}\nTech: ${techText}`).slice(0, 900) });
    stream(target, "understood", {});
    return { ok: true, target, intel: text.slice(0, 6000), tech: techText.slice(0, 2000) };
  },
  propose_chains: async (args) => {
    const target = args?.target || act();
    ensureCrate(target);
    const chains = await hexstrikeTool("create_attack_chain_ai", { target, objective: "comprehensive" });
    const disco = await hexstrikeTool("discover_attack_chains", { target_software: args?.software || target, attack_depth: 3 });
    const payload = { target, chains: pick(chains), discovery: pick(disco), proposed_at: new Date().toISOString() };
    writeChains(target, payload);
    appendDossier(target, "Proposed chains", payload.chains);
    stream(target, "reasoning", { phase: "chains", text: payload.chains.slice(0, 900) });
    stream(target, "chains_proposed", {});
    return { ok: true, target, chains: payload.chains.slice(0, 5000), discovery: payload.discovery.slice(0, 3000) };
  },
  request_approval: async (args) => {
    const target = act();
    const req = {
      id: `gate_${Date.now()}`,
      chain_id: args.chain_id,
      step: args.step ?? null,
      tool_id: args.tool_id,
      reason: args.reason || "",
      created: new Date().toISOString(),
      decision: null,
    };
    writePending(target, req);
    appendEvent(target, "approval_requested", req);
    return { ok: true, pending: req };
  },
  execute_step: async (args) => {
    const target = act();
    const st = readState(target);
    if (st.mode !== "full" || !st.armed) {
      return { refused: true, reason: "plan-mode", detail: "PLAN mode: execution refused. ARM + FULL mode to continue." };
    }
    const pend = readPending(target);
    if (st.checkpoint === "paranoid" && (!pend || pend.decision !== "approved")) {
      return { refused: true, reason: "pending-approval", pending: pend };
    }
    const entryId = args.tool_id || pend?.tool_id;
    if (!entryId) return { refused: true, reason: "missing tool_id or pending approval with tool_id" };
    writePending(target, null);
    appendEvent(target, "exec", { id: entryId });
    const result = await callEntry(entryId, target, args.args || { target });
    appendEvent(target, "exec_done", { id: entryId, ok: !!result?.ok });
    return result;
  },
  execute_plan: async (args) => {
    const target = args?.target || act();
    if (!isUsableTarget(target)) {
      return { refused: true, reason: "unusable-target", detail: `"${target}" is not a host — set a real hostname or IP.` };
    }
    const st = readState(target);
    if (st.mode !== "full" || !st.armed) {
      return { refused: true, reason: "plan-mode", detail: "PLAN mode: execution refused. ARM + FULL mode to continue." };
    }
    // Relentless: keep escalating through the arsenal until something is found,
    // bounded by maxTools / maxRounds. Set relentless:false for a single pass.
    const relentless = args.relentless !== false;
    const maxTools = Math.max(1, Number(args.max_tools || 16));
    const maxRounds = Math.max(1, Number(args.max_rounds || 6));
    const perToolTimeout = args.timeout_ms || 900000;

    const saved = readChains(target);
    let batch = extractChainSteps(saved?.chains);
    const usingChain = batch.length > 0;
    if (!batch.length) batch = defaultPlan(st.class);
    const max = Math.max(1, Number(args.max_steps || 4));
    batch = batch.slice(0, Math.min(max, batch.length));

    const results = [];
    const tried = new Set();
    let round = 0;
    let found = 0;

    const runBatch = async (steps, roundIdx, source) => {
      const names = steps.filter((s) => !tried.has(s.mcpTool)).map((s) => s.mcpTool);
      stream(target, "round_start", { round: roundIdx, source, tools: names });
      for (const step of steps) {
        if (results.length >= maxTools) break;
        if (tried.has(step.mcpTool)) continue;
        tried.add(step.mcpTool);
        const rec = await runOneTool(target, step, roundIdx, perToolTimeout);
        results.push(rec);
        found += rec.findings.length;
        if (rec.findings.length) return true;
      }
      return false;
    };

    round = 1;
    let hit = await runBatch(batch, round, usingChain ? "chain" : "default-plan");

    // Cortex sweep — use the REST of the arsenal, not just hexstrike: OSINT/recon suite
    // tools, the whois builtin, and the osint MCP upstream, all via callEntry. Always
    // runs (recon is cheap and broadens coverage), bounded by maxTools.
    {
      const sweep = (CORTEX_SWEEP[String(st.class || "other").toLowerCase()] || CORTEX_SWEEP.other).filter((id) => !tried.has(id));
      if (sweep.length && results.length < maxTools) {
        round++;
        stream(target, "round_start", { round, source: "cortex-sweep", tools: sweep });
        for (const id of sweep) {
          if (results.length >= maxTools) break;
          tried.add(id);
          const rec = await runRegistryTool(target, id, round, perToolTimeout);
          results.push(rec);
          found += rec.findings.length;
          if (rec.findings.length) hit = true;
        }
      }
    }

    while (relentless && !hit && results.length < maxTools && round < maxRounds) {
      const ladder = escalationLadder(st.class, [...tried]);
      if (!ladder.length) { stream(target, "exhausted", { tried: [...tried], findings: found }); break; }
      round++;
      const next = ladder.slice(0, 3);
      stream(target, "escalation", { round, reason: `no findings after ${results.length} tool(s) — escalating`, next: next.map((s) => s.mcpTool) });
      hit = await runBatch(next, round, "escalation");
    }

    writeState(target, { phase: "exec" });
    const st2 = readState(target);
    const negatives = results.reduce((n, r) => n + ((r.error || (r.negative && !(r.findings?.length))) ? 1 : 0), 0);
    stream(target, "hunt_done", { rounds: round, executed: results.length, findings: found, negatives, relentless });
    return {
      ok: true,
      target,
      relentless,
      rounds: round,
      executed: results.length,
      planned: batch.length,
      findings: found,
      negatives,
      findings_total: st2.findings_count || 0,
      negatives_total: st2.negatives_count || 0,
      results,
    };
  },
  save_finding: async (args) => {
    const target = act();
    const n = appendJson(target, "findings.jsonl", args);
    appendEvent(target, "finding", { title: args.title });
    return { ok: true, total: n };
  },
  save_negative: async (args) => {
    const target = act();
    const n = appendJson(target, "negatives.jsonl", args);
    return { ok: true, total: n };
  },
  ledger_report: async () => {
    const target = act();
    const st = readState(target);
    return {
      target, mode: st.mode, armed: st.armed, checkpoint: st.checkpoint, phase: st.phase, class: st.class,
      dossier_tail: readDossier(target).slice(-4000),
      findings: readJsonl(target, "findings.jsonl", 50),
      negatives: readJsonl(target, "negatives.jsonl", 50),
      pending: readPending(target),
      chains: readChains(target)?.chains?.slice(0, 4000) || null,
    };
  },
};

function pick(res) {
  if (typeof res === "string") return res;
  if (res && res.content) return res.content.map((c) => typeof c === "string" ? c : (c.text ?? JSON.stringify(c))).join("\n");
  if (res && res._meta?.["tool/listing"]) return JSON.stringify(res);
  return JSON.stringify(res, null, 2);
}

function pickText(res) {
  if (!res) return "";
  if (typeof res === "string") return res;
  if (res.content) return res.content.map((c) => (typeof c === "string" ? c : (c.text ?? JSON.stringify(c)))).join("\n");
  return JSON.stringify(res);
}

/* Run one mapped tool, streaming start -> heartbeat(s) -> output -> done so the
   dashboard shows live activity, a running timer, and liveness (not-hung) proof.
   Records findings/negatives and returns the result record. */
async function runOneTool(target, step, round, perToolTimeout) {
  const toolArgs = buildArgs(step, target);
  const start = Date.now();
  stream(target, "tool_start", { tool: step.mcpTool, chain_tool: step.tool, args: toolArgs, round });
  const hb = setInterval(() => {
    stream(target, "heartbeat", { tool: step.mcpTool, round, elapsed_ms: Date.now() - start });
  }, 4000);
  let out = null;
  let error = null;
  try {
    out = await hexstrikeTool(step.mcpTool, toolArgs, perToolTimeout);
  } catch (err) {
    error = String(err?.message || err).split("\n")[0];
  } finally {
    clearInterval(hb);
  }
  const envelope = error ? "" : pickText(out);
  let parsed = null;
  if (envelope) { try { parsed = JSON.parse(envelope); } catch {} }
  const text = error
    ? ""
    : (parsed && typeof parsed === "object"
        ? (String(parsed.stdout ?? "") + "\n" + String(parsed.stderr ?? "")).trim()
        : envelope);
  const toolErr = error ? null : detectToolError(envelope);
  if (toolErr && !error) error = toolErr.message;
  const classified = classifyOutput(text, step.mcpTool);
  const ms = Date.now() - start;
  const record = {
    tool: step.mcpTool, chain_tool: step.tool, args: toolArgs, round,
    ok: !error, error,
    findings: error ? [] : classified.findings,
    open_ports: error ? [] : classified.openPorts,
    negative: error ? null : classified.negative,
    signals: error ? [] : classified.signals,
    output_tail: text.slice(-1200), ms,
  };
  stream(target, "tool_output", { tool: step.mcpTool, round, ok: !error, tail: (error ? error : text).slice(-600), ms });
  if (error) {
    appendJson(target, "negatives.jsonl", { what: `${step.mcpTool} failed`, note: error, tool: step.mcpTool });
    stream(target, "exec_error", { id: step.mcpTool, error, round });
  }
  for (const f of record.findings) {
    appendJson(target, "findings.jsonl", { title: f.title, severity: f.severity, evidence: f.evidence, tool: step.mcpTool });
    stream(target, "finding", { title: f.title, severity: f.severity, tool: step.mcpTool, round });
  }
  if (record.negative && !record.findings.length) {
    appendJson(target, "negatives.jsonl", { what: record.negative.what, note: record.negative.note, tool: step.mcpTool });
  }
  if (record.open_ports.length) {
    stream(target, "open_ports", { tool: step.mcpTool, count: record.open_ports.length, ports: record.open_ports.slice(0, 20), round });
  }
  recordSignals(target, step.mcpTool, record.signals, round);
  stream(target, "tool_done", { id: step.mcpTool, ok: record.ok, findings: record.findings.length, signals: record.signals.length, ms, round });
  appendDossier(target, `Execution · ${step.mcpTool}`, `Args: ${JSON.stringify(toolArgs)}\n${text.slice(-3000)}`);
  return record;
}
