import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import fs from "node:fs";

const HOME = process.env.HOME;
const cfg = JSON.parse(fs.readFileSync(`${HOME}/.config/opencode/opencode.json`, "utf8"));
const results = [];
const skip = new Set(["burp-mcp", "aboutsecurity"]);

for (const [name, s] of Object.entries(cfg.mcp)) {
  if (!s.enabled || s.type !== "local" || skip.has(name)) { results.push({ name, status: "skipped" }); continue; }
  const timeout = setTimeout(() => results.push({ name, status: "timeout" }), 90000);
  try {
    const client = new Client({ name: "verify", version: "0", protocolVersion: "2025-03-26" }, { capabilities: {} }, { timeout: 90000 });
    let tr;
    if (name === "peykan") {
      tr = new SSEClientTransport(new URL("http://127.0.0.1:6278/sse"));
    } else {
      tr = new StdioClientTransport({ command: s.command[0], args: s.command.slice(1), stderr: "ignore", env: s.environment ? { ...process.env, ...s.environment } : process.env });
    }
    await client.connect(tr);
    const tools = await client.listTools();
    results.push({ name, status: "OK", tools: tools.tools.length });
    await client.close();
  } catch (err) { results.push({ name, status: "ERR", msg: String(err?.message || err).split("\n")[0].slice(0, 120) }); }
  clearTimeout(timeout);
}
for (const r of results) console.log(r.status.padEnd(8), r.name.padEnd(24), r.tools ?? "", r.msg ?? "");
