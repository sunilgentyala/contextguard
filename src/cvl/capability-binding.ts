/**
 * ContextGuard - Cryptographic Verification Layer (CVL)
 * Module: Continuous Capability Binding
 *
 * Implements Equation (2) from the paper:
 *   B_t = { (t_i, H(D_i), v_i, sigma_i) }_{i=1}^{n}
 *
 * Any discrepancy between the stored binding and the server's current
 * tool definitions triggers re-authorization (rug pull detection).
 */

import * as crypto from 'crypto';
import { ToolDefinition, generateServerKeyPair, KeyPair } from './attestation';

export interface ToolBinding {
  toolName: string;
  definitionHash: string;  // SHA-256 of canonical tool definition JSON
  version: number;
  signature: string;       // ECDSA sign(toolName || definitionHash || version)
  boundAt: number;         // Unix ms when this binding was established
}

export interface CapabilityBindingResult {
  allValid: boolean;
  violations: CapabilityViolation[];
  bindings: ToolBinding[];
}

export interface CapabilityViolation {
  toolName: string;
  type: 'definition_mutation' | 'version_rollback' | 'signature_invalid' | 'new_tool_unapproved';
  stored: string;
  current: string;
  severity: 'critical' | 'high' | 'medium';
}

function hashDefinition(tool: ToolDefinition): string {
  const canonical = JSON.stringify({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters,
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function signBinding(
  toolName: string,
  definitionHash: string,
  version: number,
  privateKey: crypto.KeyObject
): string {
  const message = `${toolName}:${definitionHash}:${version}`;
  const sign = crypto.createSign('SHA256');
  sign.update(message, 'utf8');
  return sign.sign(privateKey, 'hex');
}

function verifyBindingSignature(
  toolName: string,
  definitionHash: string,
  version: number,
  signature: string,
  publicKey: crypto.KeyObject
): boolean {
  const message = `${toolName}:${definitionHash}:${version}`;
  const verify = crypto.createVerify('SHA256');
  verify.update(message, 'utf8');
  try {
    return verify.verify(publicKey, signature, 'hex');
  } catch {
    return false;
  }
}

/** Create initial capability bindings when a server is first authorized */
export function createCapabilityBindings(
  tools: ToolDefinition[],
  privateKey: crypto.KeyObject
): ToolBinding[] {
  return tools.map((tool, _i) => {
    const definitionHash = hashDefinition(tool);
    const version = 1;
    const signature = signBinding(tool.name, definitionHash, version, privateKey);
    return {
      toolName: tool.name,
      definitionHash,
      version,
      signature,
      boundAt: Date.now(),
    };
  });
}

/**
 * Check current tool definitions against stored capability bindings.
 * This is called before every tool invocation (or periodically).
 * Returns all violations found.
 */
export function verifyCapabilityBindings(
  currentTools: ToolDefinition[],
  storedBindings: ToolBinding[],
  publicKey: crypto.KeyObject
): CapabilityBindingResult {
  const violations: CapabilityViolation[] = [];
  const storedMap = new Map(storedBindings.map(b => [b.toolName, b]));
  const currentMap = new Map(currentTools.map(t => [t.name, t]));

  // Check each stored binding against current state
  for (const binding of storedBindings) {
    const currentTool = currentMap.get(binding.toolName);
    if (!currentTool) continue; // tool removed — handled separately if needed

    // Verify signature on stored binding
    const sigValid = verifyBindingSignature(
      binding.toolName,
      binding.definitionHash,
      binding.version,
      binding.signature,
      publicKey
    );
    if (!sigValid) {
      violations.push({
        toolName: binding.toolName,
        type: 'signature_invalid',
        stored: binding.signature.slice(0, 16) + '...',
        current: 'verification failed',
        severity: 'critical',
      });
      continue;
    }

    // Check for definition mutation
    const currentHash = hashDefinition(currentTool);
    if (currentHash !== binding.definitionHash) {
      violations.push({
        toolName: binding.toolName,
        type: 'definition_mutation',
        stored: binding.definitionHash.slice(0, 16) + '...',
        current: currentHash.slice(0, 16) + '...',
        severity: 'critical',
      });
    }
  }

  // Check for new unapproved tools
  for (const [toolName] of currentMap) {
    if (!storedMap.has(toolName)) {
      violations.push({
        toolName,
        type: 'new_tool_unapproved',
        stored: '(not in binding)',
        current: 'present in tool list',
        severity: 'high',
      });
    }
  }

  return {
    allValid: violations.length === 0,
    violations,
    bindings: storedBindings,
  };
}
