import { stopSmtpServer } from "./smtp-helper";

export default async function globalTeardown() {
  await stopSmtpServer();
}
