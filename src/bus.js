/* Tiny event bus so modules outside server.js (workflow.js) can push live SSE
   events mid-execution. server.js installs the sink (its SUBS broadcast); until
   then emitLine is a no-op. Lines are already-stringified JSON event objects. */
let sink = null;

export function setSink(fn) {
  sink = fn;
}

export function emitLine(line) {
  if (!sink || !line) return;
  try { sink(line); } catch {}
}
