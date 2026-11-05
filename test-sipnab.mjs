import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const t = new StdioClientTransport({
  command: process.env.HOME + "/suite/mcps/sipnab/target/release/sipnab",
  args: ["--mcp", "-I", "/tmp/empty.pcap", "--mcp-allow-open-capture", "--mcp-file-root", process.env.HOME + "/suite/captures"],
  stderr: "pipe",
});
t.stderr.on("data", () => {});
const c = new Client({ name: "x", version: "0", protocolVersion: "2025-03-26" }, { capabilities: {} }, { timeout: 15000 });
try {
  await c.connect(t);
  const r = await c.listTools();
  console.log("SIPNAB MCP OK:", r.tools.length, "tools");
  console.log(r.tools.slice(0, 6).map((x) => x.name).join(", "));
} catch (e) { console.log("ERR", String(e).slice(0, 200)); }
process.exit(0);
