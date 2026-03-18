/**
 * agentadmit/keys.ts
 * RS256 key pair generation and loading.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

let _privateKey: string | null = null;
let _publicKey: string | null = null;

export function generateKeyPair(outputDir: string = 'keys'): { privatePath: string; publicPath: string } {
  fs.mkdirSync(outputDir, { recursive: true });

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const privatePath = path.join(outputDir, 'agentadmit_private.pem');
  const publicPath = path.join(outputDir, 'agentadmit_public.pem');

  fs.writeFileSync(privatePath, privateKey, { mode: 0o600 });
  fs.writeFileSync(publicPath, publicKey);

  // Create .gitignore
  fs.writeFileSync(path.join(outputDir, '.gitignore'), '*.pem\n');

  console.log(`[AgentAdmit] Generated RS256 key pair in ${outputDir}/`);
  return { privatePath, publicPath };
}

export function loadPrivateKey(keyPath: string = 'keys/agentadmit_private.pem'): string {
  if (_privateKey) return _privateKey;

  const envKey = process.env.AGENTADMIT_PRIVATE_KEY;
  if (envKey) {
    _privateKey = envKey;
    return _privateKey;
  }

  if (!fs.existsSync(keyPath)) {
    throw new Error(
      `Private key not found at ${keyPath}. Run 'agentadmit init' or set AGENTADMIT_PRIVATE_KEY.`
    );
  }

  _privateKey = fs.readFileSync(keyPath, 'utf-8');
  return _privateKey;
}

export function loadPublicKey(keyPath: string = 'keys/agentadmit_public.pem'): string {
  if (_publicKey) return _publicKey;

  const envKey = process.env.AGENTADMIT_PUBLIC_KEY;
  if (envKey) {
    _publicKey = envKey;
    return _publicKey;
  }

  if (!fs.existsSync(keyPath)) {
    throw new Error(
      `Public key not found at ${keyPath}. Run 'agentadmit init' or set AGENTADMIT_PUBLIC_KEY.`
    );
  }

  _publicKey = fs.readFileSync(keyPath, 'utf-8');
  return _publicKey;
}
