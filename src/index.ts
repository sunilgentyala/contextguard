/**
 * ContextGuard - Main Orchestrator
 *
 * Wires CVL + DIMS into a single verification pipeline.
 * Call verifyToolInvocation() before every MCP tool call.
 */

import { ToolDefinition, generateServerKeyPair, KeyPair, generateNonce,
         createAttestationToken, verifyAttestationToken, AttestationToken } from './cvl/attestation';
import { ToolBinding, createCapabilityBindings, verifyCapabilityBindings,
         CapabilityBindingResult } from './cvl/capability-binding';
import { SemanticFingerprint, buildFingerprint, detectDrift, scanForPoisoning,
         DriftResult, ScanResult, DEFAULT_DRIFT_THRESHOLD } from './dims/semantic-fingerprint';

export interface ServerSession {
  serverId: string;
  keyPair: KeyPair;
  currentTools: ToolDefinition[];
  capabilityBindings: ToolBinding[];
  fingerprints: Map<string, SemanticFingerprint>;
  authorizedAt: number;
}

export interface VerificationResult {
  authorized: boolean;
  toolName: string;
  cvl: {
    attestationValid: boolean;
    bindingResult: CapabilityBindingResult;
  };
  dims: {
    driftResult: DriftResult;
    scanResult: ScanResult;
  };
  latencyMs: number;
  reason?: string;
}

/**
 * Simulate server session establishment (would happen over the network
 * in a real deployment; here the server and client run in the same process
 * for testability).
 */
export function establishSession(serverId: string, tools: ToolDefinition[]): ServerSession {
  const keyPair = generateServerKeyPair();
  const capabilityBindings = createCapabilityBindings(tools, keyPair.privateKey);
  const fingerprints = new Map<string, SemanticFingerprint>();
  for (const tool of tools) {
    fingerprints.set(tool.name, buildFingerprint(tool.name, tool.description));
  }
  return {
    serverId,
    keyPair,
    currentTools: tools,
    capabilityBindings,
    fingerprints,
    authorizedAt: Date.now(),
  };
}

/**
 * Core verification pipeline — called before every tool invocation.
 * Returns a VerificationResult with sub-millisecond latency on modern hardware.
 */
export function verifyToolInvocation(
  session: ServerSession,
  toolName: string,
  currentTools: ToolDefinition[],
  driftThreshold = DEFAULT_DRIFT_THRESHOLD
): VerificationResult {
  const t0 = process.hrtime.bigint();

  // ── CVL: Attestation ───────────────────────────────────────────────────
  const nonce = generateNonce();
  const token: AttestationToken = createAttestationToken(
    session.serverId, currentTools, nonce, session.keyPair.privateKey
  );
  const attestationCheck = verifyAttestationToken(
    token, currentTools, nonce, session.keyPair.publicKey
  );

  // ── CVL: Capability Binding ────────────────────────────────────────────
  const bindingResult = verifyCapabilityBindings(
    currentTools, session.capabilityBindings, session.keyPair.publicKey
  );

  // ── DIMS: Find the specific tool being invoked ─────────────────────────
  const tool = currentTools.find(t => t.name === toolName);
  const toolDescription = tool?.description ?? '';

  const storedFingerprint = session.fingerprints.get(toolName) ?? null;
  const driftResult = detectDrift(toolName, toolDescription, storedFingerprint, driftThreshold);
  const scanResult = scanForPoisoning(toolName, toolDescription);

  // ── Authorization decision ─────────────────────────────────────────────
  const cvlPass = attestationCheck.valid && bindingResult.allValid;
  const dimsPass = !driftResult.driftDetected && scanResult.clean;
  const authorized = cvlPass && dimsPass;

  const latencyMs = Number(process.hrtime.bigint() - t0) / 1_000_000;

  let reason: string | undefined;
  if (!attestationCheck.valid) reason = `CVL Attestation: ${attestationCheck.reason}`;
  else if (!bindingResult.allValid) reason = `CVL Binding: ${bindingResult.violations.map(v => v.type).join(', ')}`;
  else if (driftResult.driftDetected) reason = `DIMS Drift: similarity=${driftResult.similarity.toFixed(3)} < threshold=${driftThreshold}`;
  else if (!scanResult.clean) reason = `DIMS Scan: ${scanResult.indicators.map(i => i.pattern).join('; ')}`;

  return {
    authorized,
    toolName,
    cvl: { attestationValid: attestationCheck.valid, bindingResult },
    dims: { driftResult, scanResult },
    latencyMs,
    reason,
  };
}

export { ToolDefinition, generateServerKeyPair, KeyPair };
