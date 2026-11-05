import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
const HOME = process.env.HOME;
const t = new StdioClientTransport({ command: `${HOME}/hexstrike-ai/hexstrike_env/bin/python`, args: [`${HOME}/hexstrike-ai/hexstrike_mcp.py`, '--server', 'http://127.0.0.1:8888'], env: process.env });
const c = new Client({ name: 'probe', version: '1' }, { capabilities: {} }, { timeout: 300000 });
await c.connect(t);
const tools = await c.listTools();
const want = ['nmap_scan','httpx_probe','katana_crawl','gau_discovery','waybackurls_discovery','nuclei_scan','gobuster_scan','dirsearch_scan','intelligent_smart_scan','ffuf_scan','wafw00f_scan','subfinder_scan','dnsenum_scan','dalfox_xss_scan','sqlmap_scan','nikto_scan','arjun_parameter_discovery','graphql_scanner','rustscan_fast_scan','masscan_high_speed'];
for (const n of want) {
  const x = tools.tools.find(y => y.name === n);
  if (!x) { console.log(`### ${n}: MISSING`); continue; }
  const props = Object.keys(x.inputSchema?.properties || {});
  const req = x.inputSchema?.required || [];
  console.log(`### ${n}`);
  console.log(`    required: ${req.join(',') || '(none)'}`);
  console.log(`    props: ${props.join(',')}`);
}
process.exit(0);
