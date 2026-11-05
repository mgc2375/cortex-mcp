import { spawn } from "node:child_process";
import fs from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const HOME = process.env.HOME;
const NODE = `${HOME}/.nvm/versions/node/v22.15.0/bin/node`;
const NPMX = `${HOME}/.nvm/versions/node/v22.15.0/bin/npx`;
const NPM_MODULES = `${HOME}/suite/mcp/cortex/node_modules`;

// mcp-shodan takes its keys ONLY as required CLI args (it exits if --shodan-api-key
// is absent and reads no env var of its own). Resolve keys from the environment, or
// from the server's own .env file, and pass them through — so dropping a key in either
// place is all it takes to light shodan up. No key is ever fabricated here.
function envOrDotenv(key, dotenvPath) {
  if (process.env[key]) return process.env[key];
  try {
    for (const line of fs.readFileSync(dotenvPath, "utf8").split("\n")) {
      const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && m[1] === key) return m[2].replace(/^["']|["']$/g, "").trim();
    }
  } catch {}
  return null;
}
function shodanCmd() {
  const base = [NODE, `${HOME}/suite/mcps/mcp-shodan/build/index.js`];
  const dotenv = `${HOME}/suite/mcps/mcp-shodan/.env`;
  const sk = envOrDotenv("SHODAN_API_KEY", dotenv);
  const vt = envOrDotenv("VIRUSTOTAL_API_KEY", dotenv);
  if (sk) base.push("--shodan-api-key", sk);
  if (vt) base.push("--virustotal-api-key", vt);
  return base;
}

export const UPSTREAMS = {
  hexstrike: {
    desc: "hexstrike-ai offensive tool fleet (~100 security tools)",
    cmd: [`${HOME}/hexstrike-ai/hexstrike_env/bin/python`, `${HOME}/hexstrike-ai/hexstrike_mcp.py`, "--server", "http://127.0.0.1:8888"],
    lazy: true,
  },
  playwright: {
    desc: "playwright browser agent for dynamic web exploitation",
    cmd: [NPMX, "-y", "@playwright/mcp@latest"],
    lazy: true,
  },
  radare2: { desc: "radare2 binary RE", cmd: [`${HOME}/.local/share/radare2/prefix/bin/r2mcp`], lazy: true },
  peykan: {
    desc: "CAN/OBD-II/UDS/J1939 simulator + MCP (virtual CAN works on mac; real bus needs Linux)",
    mode: "sse",
    url: "http://127.0.0.1:6278/sse",
    spawn: [`${HOME}/suite/mcps/pyenv2/bin/peykan`, "server"],
    lazy: true,
  },
  nuclei: {
    desc: "nuclei template scanning",
    cmd: [NPMX, "-y", "gc-nuclei-mcp"],
    env: { NUCLEI_PATH: "/opt/homebrew/bin/nuclei" },
    lazy: true,
  },
  sequential: {
    desc: "sequential-thinking reasoner",
    cmd: [NPMX, "-y", "@modelcontextprotocol/server-sequential-thinking@latest"],
    lazy: true,
  },
  ios: { desc: "ios-simulator mobile hacking", cmd: [NPMX, "-y", "ios-simulator-mcp"], lazy: false },
  context7: { desc: "library docs lookup", cmd: [NPMX, "-y", "@upstash/context7-mcp@latest"], lazy: false },
  swagger: {
    desc: "OpenAPI/Swagger spec parser",
    cmd: [NODE, `${NPM_MODULES}/swagger-mcp/dist/server.js`],
    lazy: false,
  },
  openapi: {
    desc: "openapi discovery scanner",
    cmd: [NODE, `${NPM_MODULES}/@rekl0w/mcp-openapi-discovery/dist/index.js`],
    lazy: false,
  },
  shodan: {
    desc: "Shodan + VirusTotal intel (set SHODAN_API_KEY / VIRUSTOTAL_API_KEY in env or ~/suite/mcps/mcp-shodan/.env)",
    cmd: shodanCmd(),
    lazy: true,
  },
  ghidra: {
    desc: "GhidraMCP binary RE (headless supported; needs Ghidra bridge enabled for full tools)",
    cmd: [`${HOME}/suite/mcps/pyenv/bin/ghidra-mcp`, "--transport", "stdio"],
    lazy: true,
  },
  frida: {
    desc: "frida dynamic instrumentation (userland + iOS sim)",
    cmd: [`${HOME}/suite/mcps/pyenv/bin/frida-mcp`],
    lazy: true,
  },
  jadx: {
    desc: "jadx decompiled-APK context (needs jadx bridge plugin running)",
    cmd: [`${HOME}/suite/mcps/pyenv2/bin/python`, `${HOME}/suite/mcps/jadx-mcp-server/jadx_mcp_server.py`],
    lazy: true,
  },
  hack3270: {
    desc: "mainframe TN3270/CICS pentest tooling",
    cmd: [`${HOME}/suite/mcps/pyenv/bin/python`, `${HOME}/suite/mcps/hack3270/MCPs/hack3270_mcp/hack3270_mcp.py`],
    lazy: true,
  },
  wiremcp: {
    desc: "Wireshark/pcap analysis (needs access_bpf for capture)",
    cmd: [NODE, `${HOME}/suite/mcps/WireMCP/index.js`],
    lazy: true,
  },
  sipnab: {
    desc: "SIP/RTP VoIP capture + analysis MCP (file-backed: open_capture over ~/suite/captures; live capture needs access_bpf)",
    cmd: [
      `${HOME}/suite/mcps/sipnab/target/release/sipnab`,
      "--mcp",
      "-I", `${HOME}/suite/captures/_seed.pcap`,
      "--mcp-allow-open-capture",
      "--mcp-file-root", `${HOME}/suite/captures`,
    ],
    lazy: true,
  },
  osint: {
    desc: "OSINT suite: subdomains, WHOIS, crt.sh, HIBP, username/email intel",
    cmd: [NODE, `${HOME}/suite/mcps/osint-mcp/dist/index.js`],
    lazy: true,
  },
  supplychain: {
    desc: "Supply-chain mapping & scoping: package/organization enumeration, dependency mapping, exposure analysis. Wraps osint-mcp + Shodan host fingerprinting. For full SBOM tracking, external wordlists/SBOM feeds required.",
    cmd: [NODE, `${HOME}/suite/mcps/osint-mcp/dist/index.js`],
    lazy: true,
  },
  solidaudit: {
    desc: "Solidity/web3 smart contract auditing (slither+aderyn wrappers)",
    cmd: [NODE, `${HOME}/suite/mcps/solidity-audit-mcp/dist/index.js`],
    lazy: true,
  },
  chrome: {
    desc: "Chrome DevTools protocol agent (network, console, storage)",
    cmd: [NODE, `${NPM_MODULES}/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js`],
    lazy: true,
  },
  kube: {
    desc: "Kubernetes cluster operations (needs kubeconfig)",
    cmd: [NODE, `${NPM_MODULES}/mcp-server-kubernetes/dist/index.js`],
    lazy: true,
  },
};

const pool = new Map();

function portUp(url) {
  return new Promise((resolve) => {
    try {
      const req = fetch(url, { signal: AbortSignal.timeout(2000), method: "GET" });
      req.then(() => resolve(true)).catch(() => resolve(false));
    } catch {
      resolve(false);
    }
  });
}

async function waitForUrl(url, tries = 20, delayMs = 500) {
  for (let i = 0; i < tries; i++) {
    if (await portUp(url)) return true;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return false;
}

export function spawnDetached(cmd) {
  try {
    const child = spawn(cmd[0], cmd.slice(1), { detached: true, stdio: "ignore" });
    // spawn ENOENT (missing optional binary) is emitted asynchronously, not thrown —
    // without this handler it becomes an unhandled 'error' event and crashes cortex.
    child.on("error", () => {});
    child.unref();
  } catch {}
}

export function getClient(name) {
  const u = UPSTREAMS[name];
  if (!u) throw new Error(`unknown upstream ${name}`);
  if (pool.has(name)) return pool.get(name);
  const client = new Client({ name: "cortex", version: "0.1.0", protocolVersion: "2025-03-26" }, { capabilities: {} });
  let transportPromise;
  if (u.mode === "sse") {
    transportPromise = (async () => {
      if (!(await portUp(u.url))) {
        spawnDetached(u.spawn);
        await waitForUrl(u.url);
        await new Promise((r) => setTimeout(r, 800));
      }
      return new SSEClientTransport(new URL(u.url));
    })();
  } else {
    transportPromise = Promise.resolve(
      new StdioClientTransport({
        command: u.cmd[0],
        args: u.cmd.slice(1),
        env: u.env ? { ...process.env, ...u.env } : process.env,
      })
    );
  }
  const connect = transportPromise.then((t) => client.connect(t)).then(() => client);
  const evict = () => { if (pool.get(name) === connect) pool.delete(name); };
  connect.catch(evict);      // a rejected connect (spawn ENOENT / handshake timeout) does not stick
  client.onclose = evict;    // a crashed/closed upstream self-heals: next getClient() re-spawns
  pool.set(name, connect);
  return connect;
}

export async function closeModal(name) {
  const c = pool.get(name);
  pool.delete(name);
  if (c) {
    try {
      (await c).close();
    } catch {}
  }
}

export async function listServerTools(name) {
  const client = await getClient(name);
  try {
    const res = await client.listTools();
    return (res.tools || []).map((t) => ({
      upstream: name,
      name: t.name,
      desc: (t.description || "").slice(0, 200),
    }));
  } catch (err) {
    return [];
  }
}