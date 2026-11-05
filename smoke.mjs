#!/usr/bin/env node
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";
import os from "node:os";

const HOME = os.homedir();
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(HOME, "suite/mcp/cortex/src/server.js")],
});
const client = new Client({ name: "smoke", version: "0", protocolVersion: "2025-03-26" }, { capabilities: {} });
await client.connect(transport);

const log = (...a) => console.log(...a);

const tools = await client.listTools();
log("TOOLS:", tools.tools.map((t) => t.name).join(", "));

const tri = await client.callTool({ name: "triage_target", arguments: { target: "example-cortex-test.com", class: "web" } });
log("TRIAGE:", tri.content[0].text);

const list = await client.callTool({ name: "list_tools", arguments: { class: "web" } });
log("LIST_TOOLS:", list.content[0].text.slice(0, 600));

const g = await client.callTool({ name: "request_approval", arguments: { chain_id: "c1", tool_id: "web.app.recon", reason: "smoke" } });
log("APPROVAL:", g.content[0].text);

const ex = await client.callTool({ name: "execute_step", arguments: { tool_id: "web.app.recon", args: { target: "example-cortex-test.com" } } });
log("EXEC-plan:", ex.content[0].text);

await client.close();
