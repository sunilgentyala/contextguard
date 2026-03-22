/**
 * ContextGuard - Cryptographic Verification Layer (CVL)
 * Module: Server Identity Attestation
 *
 * Implements Equation (1) from the paper:
 *   A_s = Sign_{SK_s}( H(T_list) || N || ts )
 *
 * Uses ECDSA P-256 + SHA-256 (Node.js built-in crypto).
 * No external dependencies.
 */

import * as crypto from 'crypto';

export interface KeyPair {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
}

export interface AttestationToken {
  toolListHash: string;   // hex SHA-256 of serialized tool list
  nonce: string;          // hex, 32 bytes, client-supplied
  timestamp: number;      // Unix ms
  signature: string;      // hex DER-encoded ECDSA signature
  serverId: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  version?: string;
}

/** Generate a fresh ECDSA P-256 key pair for a server */
export function generateServerKeyPair(): KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  return { privateKey, publicKey };
}

/** SHA-256 hash of the canonical JSON serialization of the tool list */
export function hashToolList(tools: ToolDefinition[]): string {
  const canonical = JSON.stringify(tools, Object.keys(tools[0] ?? {}).sort());
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/** Generate a 32-byte cryptographic nonce (client calls this) */
export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Server-side: create an attestation token binding the tool list hash,
 * the client nonce, and the current timestamp to the server's private key.
 */
export function createAttestationToken(
  serverId: string,
  tools: ToolDefinition[],
  nonce: string,
  privateKey: crypto.KeyObject
): AttestationToken {
  const toolListHash = hashToolList(tools);
  const timestamp = Date.now();

  // Message = toolListHash || nonce || timestamp (all as UTF-8 hex strings)
  const message = `${toolListHash}:${nonce}:${timestamp}`;
  const sign = crypto.createSign('SHA256');
  sign.update(message, 'utf8');
  const signature = sign.sign(privateKey, 'hex');

  return { toolListHash, nonce, timestamp, signature, serverId };
}

/**
 * Client-side: verify the attestation token.
 * Returns true only if:
 *   1. The signature is valid under the server's public key
 *   2. The nonce matches the client-supplied value
 *   3. The token is fresh (within maxAgeMs, default 30 seconds)
 *   4. The toolListHash matches the hash of the received tool list
 */
export function verifyAttestationToken(
  token: AttestationToken,
  tools: ToolDefinition[],
  expectedNonce: string,
  publicKey: crypto.KeyObject,
  maxAgeMs = 30_000
): { valid: boolean; reason?: string } {
  // Check nonce
  if (token.nonce !== expectedNonce) {
    return { valid: false, reason: 'Nonce mismatch — possible replay attack' };
  }

  // Check freshness
  const age = Date.now() - token.timestamp;
  if (age > maxAgeMs) {
    return { valid: false, reason: `Token expired (age ${age}ms > ${maxAgeMs}ms)` };
  }

  // Check tool list hash
  const expectedHash = hashToolList(tools);
  if (token.toolListHash !== expectedHash) {
    return { valid: false, reason: 'Tool list hash mismatch — tool definitions may have been tampered with in transit' };
  }

  // Verify ECDSA signature
  const message = `${token.toolListHash}:${token.nonce}:${token.timestamp}`;
  const verify = crypto.createVerify('SHA256');
  verify.update(message, 'utf8');
  try {
    const valid = verify.verify(publicKey, token.signature, 'hex');
    if (!valid) return { valid: false, reason: 'Invalid ECDSA signature' };
  } catch {
    return { valid: false, reason: 'Signature verification error' };
  }

  return { valid: true };
}
