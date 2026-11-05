# Cortex MCP

Cortex is the orchestrator at the center of a security-testing suite. It's a single MCP server that fronts ~25 upstream MCPs and a large CLI/tool arsenal, exposes them through one curated registry, and drives a structured recon → understand → chain → execute workflow with a hard safety gate between planning and firing live tools.

Point one MCP client at Cortex and you get the whole fleet — hexstrike (~100 offensive tools), Shodan/VirusTotal, OSINT, Nuclei, Playwright/Chrome DevTools, Ghidra/radare2/Frida, Kubernetes, Wireshark, a web3 auditor, and more — behind a workflow brain that tracks state per target and refuses to run anything offensive until you explicitly arm it.

## What it does

- **Aggregates upstreams.** One registry (`src/registry.js`) maps short IDs like `web.xss`, `osint.subs`, `recon.net` to the right upstream MCP, hexstrike tool, local CLI, or suite helper. Upstreams are spawned lazily and self-heal if they crash (`src/clients.js`).
- **Runs a workflow.** `triage_target → understand_target → propose_chains → execute_plan`, with findings, negatives, signals, and a dossier persisted per target in a "crate" on disk (`src/crate.js`).
- **Gates execution.** Everything runs in **PLAN** mode by default — read-only. Firing offensive tools requires switching to **FULL** mode *and* arming the target. A `checkpoint` level (`paranoid` / `normal` / `yolo`) controls whether each step needs explicit approval.
- **Streams to a dashboard.** A local sideband HTTP server (`127.0.0.1:5630`) exposes live state, an SSE event stream, and control endpoints so an external dash can drive and watch a hunt in real time (`src/bus.js`).

## Requirements

- Node.js 18+ (ES modules; upstream spawns expect an nvm Node at `~/.nvm/versions/node/v22.15.0`)
- The sibling suite layout — Cortex spawns upstreams from hard-coded paths under `~/suite/mcps`, `~/hexstrike-ai`, etc. This is built to run inside its own suite, not standalone.
- API keys for whichever upstreams you use (see Configuration)

## Install

```bash
npm install
```

## Configuration

Keys are loaded from `config.json` in the project root into the process environment at startup, so upstreams that read `process.env` pick them up. **`config.json` is git-ignored** because it holds live secrets — copy the template and fill in what you have:

```bash
cp config.example.json config.json
```

Empty values are fine; only the upstreams you actually use need keys. Shodan/VirusTotal can alternatively read `~/suite/mcps/mcp-shodan/.env`.

## Run

```bash
npm start        # node src/server.js
```

Cortex speaks MCP over stdio (add it to your MCP client config) and opens the sideband on `127.0.0.1:5630`.

## MCP tools exposed

| Tool | Purpose |
|------|---------|
| `cortex` | The workflow verb dispatcher — `triage_target`, `understand_target`, `propose_chains`, `request_approval`, `execute_step`, `execute_plan`, `save_finding`, `save_negative`, `ledger_report` |
| `list_upstreams` | List configured upstream MCPs |
| `list_tools` | List the curated registry / an upstream's tools |
| `call_tool` | Call a registry entry or upstream tool directly (offensive calls still gated by FULL+ARM) |

## Safety model

```
PLAN mode  → read/recon only, offensive tools refused
FULL + ARM → offensive execution allowed
checkpoint: paranoid → every step needs /approve
            normal   → runs, approval optional
            yolo     → no gates
```

Mode, arming, and checkpoint are toggled via the sideband (`POST /mode`, `/arm`, `/checkpoint`, `/approve`). Default state is PLAN + disarmed + normal.

## Sideband HTTP (127.0.0.1:5630)

`GET /state` · `GET /events` (SSE) · `GET /findings` · `GET /negatives` · `POST /target` · `POST /mode` · `POST /arm` · `POST /checkpoint` · `POST /approve` · `POST /execute` · `POST /call_tool` · `POST /call_upstream`

## Layout

| File | Purpose |
|------|---------|
| `src/server.js` | MCP entrypoint — stdio transport, tool dispatch, sideband HTTP server, safety gate |
| `src/registry.js` | Curated tool registry + per-class tool selection |
| `src/clients.js` | Upstream MCP definitions, lazy spawning, self-healing pool |
| `src/workflow.js` | Workflow verbs, the relentless hunt loop, Cortex sweep |
| `src/entry.js` | Dispatch to hexstrike / suite / builtin / upstream tools |
| `src/execplan.js` | Chain-step extraction, arg building, output classification, escalation ladder |
| `src/crate.js` | Per-target state, events, findings/negatives, dossier persistence |
| `src/bus.js` | SSE event bus feeding the dashboard |

`probe*.mjs`, `smoke.mjs`, `verify*.mjs`, `test-sipnab.mjs` are ad-hoc connectivity/smoke checks.

## Notes

- `config.json` is never committed. Keep real keys out of version control; rotate anything that has been in plaintext.
- `package.json` references `mcp-shodan` as a local path (`file:../../mcps/mcp-shodan`). A standalone clone won't `npm install` cleanly without that sibling folder.
- Upstream paths in `src/clients.js` are absolute and assume the suite layout under `$HOME`. Adjust them for a different environment.
