import { stopSmtpServer } from "./smtp-helper";

export default async function globalTeardown() {
  await stopSmtpServer();

  const pid = (globalThis as any).__AUTENTICO_PID__;
  if (pid) {
    console.log(`[teardown] Stopping server (PID ${pid})...`);
    try {
      process.kill(pid, "SIGTERM");
    } catch {}
  }
}
