import { createServer, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';

export interface CapturedMessage { recipients: string[]; data: string; receivedAt: number }

/** Capture real SMTP deliveries on an ephemeral loopback port within one test worker. */
export async function smtpCapture() {
  const messages: CapturedMessage[] = [];
  const sockets = new Set<Socket>();
  const server = createServer(socket => {
    sockets.add(socket); socket.setEncoding('utf8');
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => sockets.delete(socket));
    let buffer = '', dataMode = false;
    let recipients: string[] = [];
    socket.write('220 localhost SMTP fixture\r\n');
    socket.on('data', chunk => {
      buffer += chunk;
      while (true) {
        if (dataMode) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end < 0) break;
          messages.push({ recipients: [...recipients], data: buffer.slice(0, end), receivedAt: Date.now() });
          buffer = buffer.slice(end + 5); dataMode = false; recipients = [];
          socket.write('250 OK\r\n');
          continue;
        }
        const end = buffer.indexOf('\r\n');
        if (end < 0) break;
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 2);
        if (/^DATA$/i.test(line)) { dataMode = true; socket.write('354 Send message\r\n'); }
        else if (/^QUIT$/i.test(line)) { socket.end('221 Bye\r\n'); break; }
        else {
          const recipient = line.match(/^RCPT TO:\s*<([^>]+)>/i);
          if (recipient) recipients.push(recipient[1]);
          socket.write('250 OK\r\n');
        }
      }
    });
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return {
    port: (server.address() as AddressInfo).port, messages,
    async close() { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); },
    async waitFor(email: string, count: number) {
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const found = messages.filter(message => message.recipients.includes(email));
        if (found.length >= count) return found[count - 1];
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      throw new Error(`Expected SMTP message ${count} for ${email}`);
    },
  };
}
