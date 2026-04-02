export default async function globalTeardown() {
  const pid = (globalThis as any).__AUTENTICO_PID__;
  if (pid) {
    console.log(`[teardown] Stopping server (PID ${pid})...`);
    try {
      process.kill(pid, "SIGTERM");
    } catch {}
  }
}
