import { execSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";
import { startSmtpServer } from "./smtp-helper";

const ROOT = join(__dirname, "../..");
const BINARY = join(ROOT, "autentico");

export default async function globalSetup() {
  if (!existsSync(BINARY)) {
    console.log("[setup] Building Autentico...");
    execSync("make build", { cwd: ROOT, stdio: "inherit" });
  } else {
    console.log("[setup] Binary already exists, skipping build.");
  }

  await startSmtpServer(2525);
}
