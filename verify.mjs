#!/usr/bin/env node
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import fs from "node:fs";
import os from "node:os";

const HOME = os.homedir();
const cfg = JSON.parse(fs.readFileSync(`${HOME}/.config/opencode/opencode.json`, "utf8"));
const results = [];
const skip = new Set(["burp-mcp", "aboutsecurity"]); // manual/Burp-GUI-dependent

for (const [name, s] of Object.entries(cfg.mcp)) {
  if (!s.enabled || s.type !== "local" || skip.has(name)) { results.push({ name, status: "skipped" }); continue; }
  const timeout = setTimeout(() => results.push({ name, status: "timeout" }), 60000);
  try {
    const client = new Client({ name: "verify", version: "0" }, { capabilities: {} }, { timeout: 60000 });
    const transport = new StdioClientTransport({
      command: s.command[0],
      args: s.command.slice(1),
      stderr: "ignore",
      env: { ...process.env, NUCLEI_PATH: "/opt/homebrew/bin/nuclei" },
    });
    await client.connect(transport);
    const tools = await client.listTools();
    results.push({ name, status: "OK", tools: tools.tools.length });
    await client.close();
  } catch (err) {
    results.push({ name, status: "ERR", msg: String(err?.message || err).split("\n")[0].slice(0, 120) });
  }
  clearTimeout(timeout);
}
for (const r of results) console.log(r.status.padEnd(8), r.name.padEnd(18), r.tools ?? "", r.msg ?? "");
