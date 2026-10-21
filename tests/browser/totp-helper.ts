import { createHmac } from "crypto";

export function generateTOTP(base32Secret: string, timestamp = Date.now()): string {
  const time = Math.floor(timestamp / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(0, 0);
  buf.writeUInt32BE(time, 4);

  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits: number[] = [];
  for (const c of base32Secret.toUpperCase()) {
    const val = base32Chars.indexOf(c);
    if (val === -1) continue;
    for (let i = 4; i >= 0; i--) bits.push((val >> i) & 1);
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    bytes.push(byte);
  }
  const key = Buffer.from(bytes);

  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    1000000;
  return code.toString().padStart(6, "0");
}

const lastGeneratedStep = new Map<string, number>();

// Serial browser flows must wait for a new real timestep after successful use.
export async function generateFreshTOTP(base32Secret: string): Promise<string> {
  const previous = lastGeneratedStep.get(base32Secret);
  let timestamp = Date.now();
  while (previous !== undefined && Math.floor(timestamp / 30000) <= previous) {
    await new Promise(resolve => setTimeout(resolve, (previous + 1) * 30000 - Date.now() + 25));
    timestamp = Date.now();
  }
  lastGeneratedStep.set(base32Secret, Math.floor(timestamp / 30000));
  return generateTOTP(base32Secret, timestamp);
}
