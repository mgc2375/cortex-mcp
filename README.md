# Cortex MCP

Cortex is the orchestrator at the center of a security-testing suite. It's a single MCP server that fronts ~25 upstream MCPs and a large CLI/tool arsenal, exposes them through one curated registry, and drives a structured recon → understand → chain → execute workflow with a hard safety gate between planning and firing live tools.

Point one MCP client at Cortex and you get the whole fleet — hexstrike (~100 offensive tools), Shodan/VirusTotal, OSINT, Nuclei, Playwright/Chrome DevTools, Ghidra/radare2/Frida, Kubernetes, Wireshark, a web3 auditor, and more — behind a workflow brain that tracks state per target and refuses to run anything offensive until you explicitly arm it.

## What it does

- **Aggregates upstreams.** One registry (`src/registry.js`) maps short IDs like `web.xss`, `osint.subs`, `recon.net` to the right upstream MCP, hexstrike tool, local CLI, or suite helper. Upstreams are spawned lazily and self-heal if they crash (`src/clients.js`).
- **Runs a workflow.** `triage_target → understand_target → propose_chains → execute_plan`, with findings, negatives, signals, and a dossier persisted per target in a "crate" on disk (`src/crate.js`).
- **Gates execution.** Everything runs in **PLAN** mode by default — read-only. Firing offensive tools requires switching to **FULL** mode *and* arming the target. A `checkpoint` level (`paranoid` / `normal` / `yolo`) controls whether each step needs explicit approval.
- **Streams to a dashboard.** A local sideband HTTP server (`127.0.0.1:5630`) exposes live state, an SSE event stream, and control endpoints so an external dash can drive and watch a hunt in real time (`src/bus.js`).

## Requirements

- **Node.js** — install via nvm; the upstream spawn paths in `src/clients.js` expect `~/.nvm/versions/node/v22.15.0`. If you use a different version, update the `NODE`/`NPMX` constants at the top of that file.
- **The suite layout.** Cortex spawns its upstreams from hard-coded absolute paths under `$HOME` (`~/suite/mcps`, `~/hexstrike-ai`, `~/suite/mcp/suite-tools`, python venvs, homebrew binaries). It's built to run inside its own suite, not standalone. Every upstream is **lazy-spawned and optional** — a missing one just makes its tools unavailable; Cortex itself still starts.
- API keys for whichever upstreams you use (see Configuration).

## Dependencies

### 1. Local Node dependencies

```bash
npm install
```

This installs the direct deps from `package.json`: `@modelcontextprotocol/sdk`, `swagger-mcp`, `@rekl0w/mcp-openapi-discovery`, `chrome-devtools-mcp`, `mcp-server-kubernetes`, `zod`, and the local `mcp-shodan` (`file:../../mcps/mcp-shodan`).

> ⚠️ `mcp-shodan` is a **local path** dependency. The sibling `~/suite/mcps/mcp-shodan` folder must exist (and be built — see below) or `npm install` fails. For a standalone clone, remove that line from `package.json` first.

### 2. npx-fetched upstreams (automatic, no setup)

These are pulled on first use by `npx -y`, so they need no manual install — just network access the first time:

- `@playwright/mcp` — Playwright browser agent
- `gc-nuclei-mcp` — Nuclei scanning
- `@modelcontextprotocol/server-sequential-thinking` — reasoning
- `ios-simulator-mcp` — iOS simulator
- `@upstash/context7-mcp` — library docs

### 3. System binaries

```bash
brew install nuclei        # gc-nuclei-mcp expects /opt/homebrew/bin/nuclei
```

Plus, for the tools that use them: `radare2` (`r2mcp` at `~/.local/share/radare2/prefix/bin/r2mcp`), and Ghidra for the Ghidra bridge.

### 4. Sibling suite MCPs (built separately under `~/suite/mcps`)

Cortex expects these to already be installed/built in the suite. Each is its own project:

| Upstream | Path it's spawned from |
|----------|------------------------|
| `mcp-shodan` | `~/suite/mcps/mcp-shodan/build/index.js` (run its build) |
| `osint` / `supplychain` | `~/suite/mcps/osint-mcp/dist/index.js` |
| `solidaudit` | `~/suite/mcps/solidity-audit-mcp/dist/index.js` |
| `wiremcp` | `~/suite/mcps/WireMCP/index.js` |
| `sipnab` | `~/suite/mcps/sipnab/target/release/sipnab` (`cargo build --release`) |
| `jadx` | `~/suite/mcps/jadx-mcp-server/jadx_mcp_server.py` |
| `hack3270` | `~/suite/mcps/hack3270/MCPs/hack3270_mcp/hack3270_mcp.py` |
| `ghidra` | `~/suite/mcps/pyenv/bin/ghidra-mcp` |
| `frida` | `~/suite/mcps/pyenv/bin/frida-mcp` |
| `peykan` | `~/suite/mcps/pyenv2/bin/peykan` (SSE on `:6278`) |

### 5. hexstrike-ai (the main offensive fleet)

The `hexstrike` upstream (~100 tools) runs from `~/hexstrike-ai` with its own Python venv, and Cortex connects to its server on `http://127.0.0.1:8888`:

```bash
# in ~/hexstrike-ai, with its hexstrike_env venv active
python hexstrike_server.py        # start the server on :8888
```

### 6. suite-tools (the `suite.*` / `osint.*` helper arsenal)

The `kind: "suite"` registry entries shell out to `~/suite/mcp/suite-tools/run.py`, run with the hexstrike venv's Python (`~/hexstrike-ai/hexstrike_env/bin/python`). That venv needs `requests`.

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
