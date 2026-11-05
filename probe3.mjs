import { hexstrikeTool } from './src/registry.js';
const t0 = Date.now();
try {
  const r = await hexstrikeTool('nmap_scan', { target: '192.168.0.28', scan_type: '-sT -sV', ports: '22,80,443,8080,8443' }, 300000);
  const txt = (r.content || []).map(c => c.text || JSON.stringify(c)).join('\n');
  console.log('ELAPSED', ((Date.now()-t0)/1000).toFixed(1), 's');
  console.log(txt.slice(0, 1500));
} catch (e) {
  console.log('ERR after', ((Date.now()-t0)/1000).toFixed(1), 's:', e.message.slice(0,300));
}
process.exit(0);
