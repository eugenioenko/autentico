import { existsSync } from 'fs';
import { execSync } from 'child_process';
import { join } from 'path';

const ROOT = join(import.meta.dirname, '../..');
const BINARY = join(ROOT, 'autentico');

export async function setup() {
  if (existsSync(BINARY)) {
    console.log('[functional] Binary already exists, skipping build.');
  } else {
    console.log('[functional] Building binary...');
    execSync('make build-go', { cwd: ROOT, stdio: 'inherit' });
  }
}
