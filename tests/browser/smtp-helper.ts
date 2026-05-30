import { createServer, type Server } from "net";
import { createServer as createHttpServer, type Server as HttpServer } from "http";
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";

const MAIL_DIR = join(__dirname, ".smtp-mail");

export interface CapturedEmail {
  from: string;
  to: string[];
  data: string;
  receivedAt: string;
}

let smtpServer: Server | null = null;
let httpServer: HttpServer | null = null;
let emailCount = 0;

export function startSmtpServer(port = 2525, httpPort = 2526): Promise<void> {
  if (!existsSync(MAIL_DIR)) mkdirSync(MAIL_DIR, { recursive: true });
  writeFileSync(join(MAIL_DIR, "count"), "0");

  return new Promise((resolve, reject) => {
    smtpServer = createServer((socket) => {
      const email: Partial<CapturedEmail> = { to: [] };
      let mode = "command";
      let dataBuffer = "";

      socket.write("220 localhost SMTP Test Server\r\n");

      socket.on("data", (chunk) => {
        const lines = chunk.toString();

        if (mode === "data") {
          dataBuffer += lines;
          if (dataBuffer.includes("\r\n.\r\n")) {
            email.data = dataBuffer.replace(/\r\n\.\r\n$/, "");
            email.receivedAt = new Date().toISOString();
            emailCount++;
            writeFileSync(
              join(MAIL_DIR, `email-${emailCount}.json`),
              JSON.stringify(email)
            );
            writeFileSync(join(MAIL_DIR, "count"), String(emailCount));
            mode = "command";
            dataBuffer = "";
            socket.write("250 OK\r\n");
          }
          return;
        }

        for (const line of lines.split("\r\n")) {
          const cmd = line.trim().toUpperCase();
          if (!cmd) continue;

          if (cmd.startsWith("EHLO") || cmd.startsWith("HELO")) {
            socket.write("250 localhost\r\n");
          } else if (cmd.startsWith("MAIL FROM:")) {
            email.from = line
              .replace(/^MAIL FROM:\s*/i, "")
              .replace(/[<>]/g, "");
            socket.write("250 OK\r\n");
          } else if (cmd.startsWith("RCPT TO:")) {
            email.to!.push(
              line.replace(/^RCPT TO:\s*/i, "").replace(/[<>]/g, "")
            );
            socket.write("250 OK\r\n");
          } else if (cmd === "DATA") {
            mode = "data";
            dataBuffer = "";
            socket.write("354 Send data\r\n");
          } else if (cmd === "QUIT") {
            socket.write("221 Bye\r\n");
            socket.end();
          } else {
            socket.write("250 OK\r\n");
          }
        }
      });
    });

    smtpServer.on("error", reject);
    smtpServer.listen(port, () => {
      console.log(`[smtp] Fake SMTP server listening on port ${port}`);

      // HTTP API to read captured emails from test workers
      httpServer = createHttpServer((req, res) => {
        res.setHeader("Content-Type", "application/json");
        if (req.url === "/emails/last") {
          const count = parseInt(
            readFileSync(join(MAIL_DIR, "count"), "utf-8")
          );
          if (count === 0) {
            res.end(JSON.stringify(null));
            return;
          }
          const data = readFileSync(
            join(MAIL_DIR, `email-${count}.json`),
            "utf-8"
          );
          res.end(data);
        } else if (req.url === "/emails/clear") {
          emailCount = 0;
          writeFileSync(join(MAIL_DIR, "count"), "0");
          res.end(JSON.stringify({ cleared: true }));
        } else {
          res.end(JSON.stringify({ count: emailCount }));
        }
      });

      httpServer.listen(httpPort, () => {
        console.log(`[smtp] Email API listening on port ${httpPort}`);
        resolve();
      });
    });
  });
}

export function stopSmtpServer(): Promise<void> {
  return new Promise((resolve) => {
    let remaining = 2;
    const done = () => {
      if (--remaining === 0) resolve();
    };
    if (smtpServer) {
      smtpServer.close(done);
      smtpServer = null;
    } else done();
    if (httpServer) {
      httpServer.close(done);
      httpServer = null;
    } else done();
  });
}

// --- Client-side helpers (used in test workers via HTTP) ---

const EMAIL_API = "http://localhost:2526";

export async function getLastEmail(): Promise<CapturedEmail | null> {
  const resp = await fetch(`${EMAIL_API}/emails/last`);
  return resp.json();
}

export async function clearEmails(): Promise<void> {
  await fetch(`${EMAIL_API}/emails/clear`);
}

export async function waitForNewEmail(timeout = 5000): Promise<CapturedEmail> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const email = await getLastEmail();
    if (email) return email;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("No email received within timeout");
}

export function extractMagicLinkCode(email: CapturedEmail): string | null {
  const decoded = decodeEmailBody(email.data);
  const match = decoded.match(/(\d{6})/);
  return match ? match[1] : null;
}

export function extractMagicLinkURL(email: CapturedEmail): string | null {
  const decoded = decodeEmailBody(email.data);
  const match = decoded.match(/href="([^"]*magic-link\/verify[^"]*)"/);
  return match ? match[1] : null;
}

export function extractLink(email: CapturedEmail, pathContains: string): string | null {
  const decoded = decodeEmailBody(email.data);
  const re = new RegExp(`href="([^"]*${pathContains}[^"]*)"`, "i");
  const match = decoded.match(re);
  return match
    ? match[1]
        .replace(/&amp;/g, "&")
        .replace(/&#43;/g, "+")
        .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    : null;
}

function decodeEmailBody(raw: string): string {
  const bodyStart = raw.indexOf("\r\n\r\n");
  const body = bodyStart >= 0 ? raw.slice(bodyStart + 4) : raw;

  if (raw.toLowerCase().includes("quoted-printable")) {
    return body
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
  }
  return body;
}
